from loguru import logger
import sys

# Use Loguru for logging
logger.remove()
logger.add(sys.stdout, format="{message}", serialize=True)


def get_logger():
    return logger
