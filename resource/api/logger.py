from loguru import logger
import sys


logger.remove()
logger.add(sys.stdout, serialize=True)


def get_logger():
    return logger
