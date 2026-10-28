import os


MAX_CONTENT_LENGTH = 16 * 1024
MAX_URL_LENGTH = 2048
SECRET_KEY = os.environ.get("PHISHLENS_SECRET_KEY", "development-only-key")
