from loguru import logger
import sys
from uvicorn.config import LOGGING_CONFIG


logger.remove()
logger.add(sys.stdout, serialize=True)


def get_logger():
    return logger
