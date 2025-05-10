import logging
from downloader import NASAImageDownloader

# Setup logging
logging.basicConfig(level=logging.INFO)

def main():
    # Create an instance of NASAImageDownloader with the folder to store images
    download_folder = "nasa_images"
    downloader = NASAImageDownloader(download_folder)

    try:
        logging.info("Starting the download process...")

        # Start the WebDriver
        logging.info("Starting WebDriver...")
        downloader.start_driver()

        # Get the image URLs
        logging.info("Navigating to NASA images website...")
        image_urls = downloader.get_results()

        # If images are found, download them
        if image_urls:
            logging.info(f"Found {len(image_urls)} images.")
            downloader.download_images(image_urls)
        else:
            logging.info("No images found.")

    except Exception as e:
        logging.error(f"An error occurred: {e}")

    finally:
        # Close the WebDriver
        logging.info("Closing WebDriver...")
        downloader.close_driver()

if __name__ == "__main__":
    main()

