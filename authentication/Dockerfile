FROM python:3.12-alpine as builder
RUN pip install pipenv

WORKDIR /code
COPY Pipfile* /code
RUN pip install pipenv
RUN pipenv install --system --deploy
RUN python -c "import uvicorn; print(uvicorn.__version__)"
COPY ./api /code/api
EXPOSE 8080
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8080"]