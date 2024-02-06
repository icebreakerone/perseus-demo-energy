import base64

from fastapi import FastAPI, Request

app = FastAPI()


@app.middleware("http")
async def add_client_certificate(request: Request, call_next):
    # Check if the "X-SSL-Client-Cert" header already exists
    # Call the next middleware or the main application
    response = await call_next(request)
    if "X-SSL-Client-Cert" not in request.headers:
        # Retrieve the client certificate information from request.scope
        tls = request.scope.get("tls", {})
        client_certificate = tls.get("client_certificate")

        # Access certificate information and add it to headers
        if client_certificate:
            # Convert the client certificate to Base64
            cert_base64 = base64.b64encode(client_certificate).decode("utf-8")

            # Add the certificate information to the headers
            response.headers["X-SSL-Client-Cert"] = cert_base64
            # request.scope["headers"] = headers.raw

    return response


# @app.middleware("http")
# async def add_process_time_header(request: Request, call_next):
#     start_time = time.time()
#     response = await call_next(request)
#     process_time = time.time() - start_time
#     response.headers["X-Process-Time"] = str(process_time)
#     return response
