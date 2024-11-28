import logging
from logging.handlers import RotatingFileHandler

LOG_FILE = "files/password_manager.log"

def setup_logger():
    """Set up the logger"""
    logger = logging.getLogger("PasswordManager")
    logger.setLevel(logging.INFO)

    handler = RotatingFileHandler(LOG_FILE, maxBytes=1_048_576, backupCount=5)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)

    logger.addHandler(handler)
    return logger

logger = setup_logger()