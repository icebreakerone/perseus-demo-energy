FROM python:3.12-slim
RUN pip install pipenv
COPY Pipfile* /code/
WORKDIR /code
RUN pipenv install --system --deploy --ignore-pipfile
COPY ./api /code/api
EXPOSE 8080
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8080"]