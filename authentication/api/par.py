import secrets
import redis
import json
import base64


def redis_connection() -> redis.Redis:
    return redis.Redis(host="redis", port=6379, db=0, decode_responses=True)


def get_token(byte_length: int = 20) -> str:  # 160 bits / 8 bits per byte = 20 bytes
    token_bytes = secrets.token_bytes(byte_length)
    return base64.urlsafe_b64encode(token_bytes).decode().rstrip("=")


def store_request(token: str, request: dict):
    connection = redis_connection()
    connection.set(token, json.dumps(request))
    connection.expire(token, 60)  # 1 minute


def get_request(token: str) -> dict:
    connection = redis_connection()
    request = connection.get(token)
    return json.loads(str(request))
