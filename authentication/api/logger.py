from loguru import logger
import sys

# loguru defaults backtrace and diagnose to True. diagnose annotates every frame
# of a traceback with its local variables, which puts access tokens, refresh
# tokens and signing keys into the logs on any unhandled exception, and backtrace
# extends the trace up through the whole ASGI stack. Both are off.
logger.remove()
logger.add(sys.stdout, format="{message}", backtrace=False, diagnose=False)


def get_logger():
    return logger
