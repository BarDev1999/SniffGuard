import logging
import re
from logging.handlers import RotatingFileHandler

def setup_logger(log_file_name: str) -> logging.Logger:
    """
    Set up a rotating file logger.
    Why:
    - Prevents the log file from growing without bounds.
    - Keeps a few backups for later investigation.
    """
    log_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    handler = RotatingFileHandler(log_file_name, maxBytes=5_000_000, backupCount=3)
    handler.setFormatter(log_formatter)

    logger_obj = logging.getLogger("ids_logger")
    logger_obj.setLevel(logging.getLogger().level)  # inherit root level set by CLI
    # Avoid adding multiple handlers if setup_logger is called more than once
    if not any(isinstance(h, RotatingFileHandler) for h in logger_obj.handlers):
        logger_obj.addHandler(handler)

    return logger_obj
    
def to_safe_filename(s: str) -> str:
    """
    Sanitize a string for safe use in filenames.
    Example: convert IP or interface names into valid file components.
    """
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", s)[:100]
