import os
import time
import requests
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


class NASAImageDownloader:
    def __init__(self, download_folder):
        self.base_url = "https://images.nasa.gov"
        self.download_folder = download_folder
        self.driver = None

    def start_driver(self):
        # Setup Chrome WebDriver
        chrome_options = webdriver.ChromeOptions()
        chrome_options.add_argument("--headless")  # Optional: Runs browser in the background
        chrome_options.add_argument("--no-sandbox")  # For Docker environments
        chrome_options.add_argument("--disable-dev-shm-usage")  # For Docker environments
        self.driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)
        print("WebDriver started.")

    def get_mission_page_urls(self):
        if self.driver is None:
            raise Exception("WebDriver is not initialized. Call start_driver() first.")

        self.driver.get(self.base_url)
        time.sleep(2)  # Wait for the page to load

        # Collect the URLs of individual mission pages (from the NASA Images site)
        mission_links = []
        links = self.driver.find_elements(By.XPATH, "//a[contains(@href, 'details')]")  # Find all detail page links
        for link in links:
            url = link.get_attribute("href")
            if url and "details" in url:
                mission_links.append(url)
        
        print(f"Found {len(mission_links)} mission links.")
        return mission_links

    def get_images_from_mission_page(self, mission_url):
        self.driver.get(mission_url)
        time.sleep(2)  # Wait for the page to load

        # Get all image elements on the mission page
        image_urls = []
        images = self.driver.find_elements(By.TAG_NAME, "img")
        for img in images:
            src = img.get_attribute("src")
            if src and "nasa.gov" in src and "logo" not in src:  # Ignore logos and icons
                image_urls.append(src)
        
        print(f"Found {len(image_urls)} images on the mission page {mission_url}.")
        return image_urls

    def download_images(self, image_urls):
        if not os.path.exists(self.download_folder):
            os.makedirs(self.download_folder)

        for img_url in image_urls:
            try:
                img_data = requests.get(img_url).content
                img_name = img_url.split("/")[-1]
                img_path = os.path.join(self.download_folder, img_name)

                with open(img_path, "wb") as img_file:
                    img_file.write(img_data)

                print(f"Downloaded {img_name}")

            except Exception as e:
                print(f"Failed to download {img_url}: {e}")

    def close_driver(self):
        if self.driver:
            self.driver.quit()
            print("WebDriver closed.")
        else:
            print("Driver is already None, cannot close.")

