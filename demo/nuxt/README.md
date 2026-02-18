# Nuxt OIDC Demo

A simple demo showing how a web app can connect to an OIDC server that uses [VC-AuthN OIDC](https://github.com/bcgov/vc-authn-oidc) as an identity provider to authenticate users via verifiable credentials.

Logging in will route through the Keycloak instance that has VC-AuthN OIDC configured as an IDP and then return to the app, showing the authenticated token and VC claims. The dashboard also includes a **"Call Secured API Route"** button that demonstrates a protected Nitro API endpoint — only accessible with a valid session.

## Prerequisites

- VCAuthN must be running locally. See the [parent repo](../../README.md) for startup instructions.
- ngrok is used as part of this flow. You may see an ngrok interstitial warning in your browser — click through to continue.

## Running with Docker Compose

```bash
docker compose build
docker compose up
```

The app will be available at http://localhost:8080.

Set `NUXT_PUBLIC_PRES_REQ_CONF_ID` to your presentation request configuration ID (e.g. `showcase-person`). See `docker-compose.yaml` for all variables.

## Local Development of Demo

```bash
npm install
npm run dev
```

You'll need to set the environment variables from `docker-compose.yaml` manually, either as shell exports or in a `.env` file.
