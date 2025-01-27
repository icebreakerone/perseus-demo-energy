from os import path
import json

from .main import app
from fastapi.testclient import TestClient
from .conf import DIRNAME

output_dir = f"{path.dirname(DIRNAME)}/output"

client = TestClient(app)
response = client.get("/api-docs")

with open(f"{output_dir}/openapi.json", "w+") as f:
    json.dump(app.openapi(), f)
with open(f"{output_dir}/index.html", "w+") as f:
    f.write(response.content.decode("utf-8"))
