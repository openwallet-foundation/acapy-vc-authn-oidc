[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE) [![unit-tests](https://github.com/openwallet-foundation/acapy-vc-authn-oidc/actions/workflows/controller_unittests.yml/badge.svg?branch=main&event=push)](https://github.com/openwallet-foundation/acapy-vc-authn-oidc/actions/workflows/controller_unittests.yml) [![Coverage Status](https://coveralls.io/repos/github/openwallet-foundation/acapy-vc-authn-oidc/badge.svg?branch=main)](https://coveralls.io/github/openwallet-foundation/acapy-vc-authn-oidc?branch=main)

# Verifiable Credential Authentication with OpenID Connect (VC-AuthN OIDC)

Verifiable Credential Identity Provider for OpenID Connect.

See [here](/docs/README.md) for background into how this integration is defined.

For configuration instructions, refer to the [configuration guide](/docs/ConfigurationGuide.md).

Make sure to read the [best practices](/docs/BestPractices.md) to be used when protecting a web application using `vc-authn-oidc`.

If you are upgrading from a previous release, take a look at the [migration guide](/docs/MigrationGuide.md).

## Pre-requisites

- A bash-compatible shell such as [Git Bash](https://git-scm.com/downloads)
- [Docker](https://docs.docker.com/get-docker/)
- Ngrok token (optional, required for local development)

## Configuring Ngrok

Each developer must apply for an Ngrok token [here](https://dashboard.ngrok.com/get-started/your-authtoken). Then place the token into the .env-dev file within the docker directory.

```
NGROK_AUTHTOKEN=<your token here>
```

## Running VC-AuthN

Open a shell in the [docker](docker/) folder and run the following commands:

- `./manage build`: this command will build the controller image. This step is required the first time the project is run, and when dependencies change in the requirements file(s).
- `./manage start`: this will start the project with **multiple controller pods by default** for scalability. Follow the script prompts to select the appropriate runtime options: they will be saved in an `env` file for the next execution.
- To reset everything (including removing container data and selected options in the `env` file) execute `./manage rm`.

### Additional Commands

- `./manage single-pod`: Run single pod setup for debugging
- `./manage scale <number>`: Scale to specific number of controller pods
- `CONTROLLER_REPLICAS=<number> ./manage start`: Set replica count via environment

A list of all available commands is visible by executing `./manage -h`.

The project is set-up to run without needing any external dependencies by default, using a standalone agent in read-only that will target the ledgers specified in [ledgers.yaml](docker/agent/config/ledgers.yaml).

## Using VC-AuthN

To use VC-AuthN for development and/or demo purposes, a pre-configured demo app is provided in the [demo/vue](demo/vue/) folder. To start it, execute `docker compose up` from within the `demo/vue` folder.

In order to use the VC OIDC authentication, a couple of extra steps are required:

- A proof-request configuration needs to be registered with VC-AuthN. To do
  so, the following command can be used to post a configuration requesting a BC Wallet Showcase Person credential:
- Though not implemented in this built-in config, proof-request configurations can optionally include substitution variables. Details can be found [here](docs/ConfigurationGuide.md#proof-substitution-variables)

```bash
curl -X 'POST' \
  'http://localhost:5000/ver_configs/' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "ver_config_id": "showcase-person",
  "subject_identifier": "",
  "generate_consistent_identifier": true,
  "proof_request": {
    "name": "BC Wallet Showcase Person",
    "version": "1.0",
    "requested_attributes": [

      {
        "names": ["given_names", "family_name", "country"],
        "restrictions": [
          {
            "schema_name": "Person",
            "issuer_did": "QEquAHkM35w4XVT3Ku5yat"
          }
        ]
      }
    ],
    "requested_predicates": []
  }
}'
```

- The demo application is configured to use Keycloak as AIM system. To register keycloak as a client for VC-AuthN, execute the following command in a shell:

```bash
curl -X 'POST' \
  'http://localhost:5000/clients/' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "client_id": "keycloak",
  "client_name": "keycloak",
  "client_secret": "**********",
  "response_types": [
    "code",
    "id_token",
    "token"
  ],
  "token_endpoint_auth_method": "client_secret_basic",
  "redirect_uris": [
    "http://localhost:8880/auth/realms/vc-authn/broker/vc-authn/endpoint"
  ]
}'
```

- Lastly, obtain a Person Credential from the [BC Wallet Showcase](https://digital.gov.bc.ca/digital-trust/showcase) by completing the lawyer demo.

After all these steps have been completed, you should be able to authenticate with the demo application using the "Verified Credential Access" option.

## Debugging

To connect a debugger to the `vc-authn` controller service, start the project using `DEBUGGER=true ./manage start` and then launch the debugger, it should connect automatically to the container.

This is a sample debugger launch configuration for VSCode that can be used by adding it to `launch.json`, it assumes a `.venv` folder containing the virtual environment was created in the repository root:

```json
{
  "version": "0.1.1",
  "configurations": [
    {
      "name": "Python: Debug VC-AuthN Controller",
      "type": "python",
      "request": "attach",
      "port": 5678,
      "host": "localhost",
      "pathMappings": [
        {
          "localRoot": "${workspaceFolder}/oidc-controller",
          "remoteRoot": "/app"
        },
        {
          "localRoot": "${workspaceFolder}/.venv/Lib/site-packages",
          "remoteRoot": "/usr/local/lib/python3.12/site-packages"
        }
      ],
      "justMyCode": false
    }
  ]
}
```
