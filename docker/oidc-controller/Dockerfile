FROM python:3.12 AS main

WORKDIR /app/src

# Metadata labels following OCI Image Format Specification
LABEL org.opencontainers.image.title="ACA-Py VC-AuthN OIDC Controller"
LABEL org.opencontainers.image.description="OpenID Connect Identity Provider powered by Verifiable Credentials using ACA-Py"
LABEL org.opencontainers.image.url="https://github.com/openwallet-foundation/vc-authn-oidc"
LABEL org.opencontainers.image.documentation="https://github.com/openwallet-foundation/vc-authn-oidc/blob/main/README.md"
LABEL org.opencontainers.image.source="https://github.com/openwallet-foundation/vc-authn-oidc"
LABEL org.opencontainers.image.vendor="OpenWallet Foundation"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.authors="OpenWallet Foundation"

ENV POETRY_VIRTUALENVS_CREATE=false
RUN pip3 install --no-cache-dir poetry==2.0

COPY pyproject.toml poetry.lock README.md ./
RUN poetry install --no-root --only main

COPY ./oidc-controller .
COPY ./html-templates /app/controller-config/templates

EXPOSE 5000

RUN ["chmod", "+x", "./docker-entrypoint.sh"]

ENTRYPOINT ["./docker-entrypoint.sh"]
