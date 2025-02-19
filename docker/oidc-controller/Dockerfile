FROM python:3.12 AS main

WORKDIR /app

ENV POETRY_VIRTUALENVS_CREATE=false
RUN pip3 install --no-cache-dir poetry==2.0

COPY pyproject.toml poetry.lock README.md ./
RUN poetry install --no-root --only main

COPY ./oidc-controller .
COPY ./html-templates /etc/controller-config/templates

EXPOSE 5000

RUN ["chmod", "+x", "./docker-entrypoint.sh"]

ENTRYPOINT ["./docker-entrypoint.sh"]
