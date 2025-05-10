import time
import logging
from functools import wraps

# Setup logger
logger = logging.getLogger(__name__)

def retry_on_exception(max_retries=3, backoff_factor=2):
    """Decorator for retrying functions with exponential backoff."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            retries = 0
            delay = 1
            while retries < max_retries:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    logger.warning(f"{e}, Retrying in {delay} seconds...")
                    time.sleep(delay)
                    retries += 1
                    delay *= backoff_factor
            raise Exception(f"Max retries exceeded for {func.__name__}")
        return wrapper
    return decorator

