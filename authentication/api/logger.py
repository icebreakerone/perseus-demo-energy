import datetime
import json
import sys
import traceback

from loguru import logger


def _as_json(record) -> None:
    """
    Render a record as one flat JSON object, so CloudWatch Logs Insights finds
    every field without unwrapping it. Fields bound with logger.bind or
    logger.contextualize become top level keys.

    A traceback is rendered with the standard library, which never includes
    frame locals, and kept inside the object so it stays one log event.
    """
    entry = {
        "timestamp": record["time"].astimezone(datetime.timezone.utc).isoformat(),
        "level": record["level"].name,
        "message": record["message"],
    }
    entry.update(
        (key, value) for key, value in record["extra"].items() if key != "_json"
    )
    if record["exception"] is not None:
        kind, value, trace = record["exception"]
        entry["exception"] = "".join(traceback.format_exception(kind, value, trace))
    record["extra"]["_json"] = json.dumps(entry, default=str)


def _format(record) -> str:
    # A callable format stops loguru appending its own traceback after the JSON
    return "{extra[_json]}\n"


# loguru defaults backtrace and diagnose to True. diagnose annotates every frame
# of a traceback with its local variables, which puts access tokens, refresh
# tokens and signing keys into the logs on any unhandled exception, and backtrace
# extends the trace up through the whole ASGI stack. Both are off.
logger.remove()
logger.configure(patcher=_as_json)
logger.add(sys.stdout, format=_format, backtrace=False, diagnose=False)


def get_logger():
    return logger
