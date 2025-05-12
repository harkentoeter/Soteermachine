#!/usr/bin/env python3

import argparse
import json
import os
import re
import requests
import time
from dataclasses import dataclass
from typing import List, Optional
from rich.console import Console
from rich.table import Table

console = Console()

@dataclass
class Vulnerability:
    cve_id: str
    cvss_score: Optional[float]

@dataclass
class PortInfo:
    port: int
    protocol: str
    state: str
    service: Optional[str] = None
    version: Optional[str] = None
    vulnerabilities: Optional[List[Vulnerability]] = None

def parse_nmap_output(filepath: str) -> List[PortInfo]:
    """Parses a simple Nmap grepable-like output file"""
    if not os.access(filepath, os.R_OK):
        raise ValueError(f"[!] Cannot read input file: {filepath}")

    port_info_list: List[PortInfo] = []
    with open(filepath, "r") as f:
        for line in f:
            match = re.match(r"(\d+)/([a-z]+)\s+(\w+)\s+(\S.+)", line)
            if not match:
                continue

            port, protocol, state, service_version = match.groups()
            service, version = None, None

            service_version = service_version.strip()
            # Split first token as service name, rest as version string
            tokens = service_version.split(maxsplit=1)
            if len(tokens) == 2:
                service, version = tokens
            elif len(tokens) == 1:
                service = tokens[0]

            port_info_list.append(
                PortInfo(
                    port=int(port),
                    protocol=protocol,
                    state=state,
                    service=service,
                    version=version,
                    vulnerabilities=[]
                )
            )

    return port_info_list

def clean_service_version(service: str, version: str) -> str:
    """Simplifies service/version string for effective CVE querying"""
    service = service.lower().strip()
    version = version.lower().strip()

    version = re.sub(r'\(.*?\)', '', version)  # Remove text inside ()
    version = re.sub(r'debian|ubuntu|centos|redhat|rhel|fedora|suse|el\d?', '', version, flags=re.IGNORECASE)
    version = re.sub(r'[^a-zA-Z0-9\.\- ]', '', version)  # Remove non-alphanum except dot/dash/space
    version = version.strip()

    version_match = re.search(r'\d+\.\d+', version)
    short_version = version_match.group() if version_match else ""

    keywords = f"{service} {short_version}".strip()
    return keywords

def get_cves(service: str, version: str) -> List[Vulnerability]:
    """Queries NVD API and returns relevant CVEs with CVSS v3 scores"""
    keywords = clean_service_version(service, version).replace(" ", "+")
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    query_params = {
        "keywordSearch": keywords,
        "startIndex": 0,
        "resultsPerPage": 20,
        "sortBy": "cvssV3BaseScore",
        "sortOrder": "desc"
    }

    vulnerabilities: List[Vulnerability] = []
    console.print(f"[cyan][~] Fetching CVEs for [bold]{service} {version}[/]...[/]")

    try:
        response = requests.get(url, params=query_params, timeout=15)
        response.raise_for_status()
        data = response.json()

        for item in data.get("vulnerabilities", []):
            cve_id = item.get("cve", {}).get("id", "")
            cvss_score = None
            metrics = item.get("cve", {}).get("metrics", {})
            if "cvssMetricV31" in metrics:
                cvss_score = metrics["cvssMetricV31"][0]["cvssData"].get("baseScore")
            elif "cvssMetricV30" in metrics:
                cvss_score = metrics["cvssMetricV30"][0]["cvssData"].get("baseScore")

            if cve_id:
                vulnerabilities.append(Vulnerability(cve_id=cve_id, cvss_score=cvss_score))

        time.sleep(1.5)  # Respectful delay to avoid API throttling

    except Exception as e:
        console.print(f"[bold red][!] Failed to fetch CVEs for {keywords}: {e}[/]")

    return vulnerabilities

def generate_table(port_info_list: List[PortInfo]) -> Table:
    """Generates a rich table object with port info and vulnerabilities"""
    table = Table(title="🔍 Nmap Scan Report (with CVEs)", style="bold white")
    table.add_column("Port", style="cyan", justify="center")
    table.add_column("Proto", style="cyan", justify="center")
    table.add_column("State", style="green", justify="center")
    table.add_column("Service", style="magenta")
    table.add_column("Version", style="magenta")
    table.add_column("Vulnerabilities", style="red")

    for port_info in port_info_list:
        vuln_summary = "-"
        if port_info.vulnerabilities:
            vuln_summary = "\n".join([f"{v.cve_id} (CVSS: {v.cvss_score})" if v.cvss_score else v.cve_id for v in port_info.vulnerabilities])

        table.add_row(
            str(port_info.port),
            port_info.protocol,
            port_info.state,
            port_info.service or "-",
            port_info.version or "-",
            vuln_summary
        )

    return table

def save_output(port_info_list: List[PortInfo], output_file: str, format: str):
    """Saves output in chosen format"""
    if format == "table":
        table = generate_table(port_info_list)
        with open(output_file, "w") as f:
            f.write(table.__rich_console__(console, console.options).__next__().text)
        console.print(f"[bold green][+] Output saved to {output_file}[/]")
    elif format == "json":
        json_data = []
        for port in port_info_list:
            json_data.append({
                "port": port.port,
                "protocol": port.protocol,
                "state": port.state,
                "service": port.service,
                "version": port.version,
                "vulnerabilities": [{"cve_id": v.cve_id, "cvss_score": v.cvss_score} for v in port.vulnerabilities]
            })
        with open(output_file, "w") as f:
            json.dump(json_data, f, indent=4)
        console.print(f"[bold green][+] JSON output saved to {output_file}[/]")
    else:
        console.print(f"[bold red][!] Unsupported format: {format}[/]")

def main():
    parser = argparse.ArgumentParser(description="Parse Nmap output and enrich with CVEs")
    parser.add_argument("-i", "--input", required=True, help="Nmap output file (custom text format)")
    parser.add_argument("-o", "--output", required=True, help="Output file path")
    parser.add_argument("-f", "--format", choices=["table", "json"], default="table", help="Output format (default: table)")
    args = parser.parse_args()

    port_info_list = parse_nmap_output(args.input)

    for port in port_info_list:
        if port.service and port.version:
            port.vulnerabilities = get_cves(port.service, port.version)

    table = generate_table(port_info_list)
    console.print(table)

    save_output(port_info_list, args.output, args.format)

if __name__ == "__main__":
    main()

