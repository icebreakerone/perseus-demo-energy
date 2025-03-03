FROM python:3.12-slim
# Should be removed once the package is public
ARG PROVENANCE_INSTALL_TOKEN 
RUN apt update && apt install -y git
RUN pip install pipenv
COPY Pipfile* /code/
WORKDIR /code
RUN pipenv install --system --deploy --ignore-pipfile
COPY ./api /code/api
COPY ./data /code/data
EXPOSE 8080
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8080", "--log-level", "info", "--access-log"]