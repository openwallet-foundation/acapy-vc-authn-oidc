[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE) [![unit-tests](https://github.com/openwallet-foundation/acapy-vc-authn-oidc/actions/workflows/controller_unittests.yml/badge.svg?branch=main&event=push)](https://github.com/openwallet-foundation/acapy-vc-authn-oidc/actions/workflows/controller_unittests.yml) [![Coverage Status](https://coveralls.io/repos/github/openwallet-foundation/acapy-vc-authn-oidc/badge.svg?branch=main)](https://coveralls.io/github/openwallet-foundation/acapy-vc-authn-oidc?branch=main)

# Verifiable Credential Authentication with OpenID Connect (VC-AuthN OIDC)

Verifiable Credential Identity Provider for OpenID Connect.

See [here](/docs/README.md) for background into how this integration is defined.

For configuration instructions, refer to the [configuration guide](/docs/ConfigurationGuide.md).

Make sure to read the [best practices](/docs/BestPractices.md) to be used when protecting a web application using `vc-authn-oidc`.

If you are upgrading from a previous release, take a look at the [migration guide](/docs/MigrationGuide.md).

For information about prover-role functionality (when VC-AuthN responds to proof requests), see the [prover role logging documentation](/docs/ProverRoleLogging.md).

## Pre-requisites

- A bash-compatible shell such as [Git Bash](https://git-scm.com/downloads)
- [Docker](https://docs.docker.com/get-docker/)
- Ngrok token (optional, required for local development)

## Running VC-AuthN

Open a shell in the [docker](docker/) folder and run the following commands:

- `cp .env.example .env` to create a local environment variable file.
- Update `.env` with your `NGROK_AUTHTOKEN` and customize environment variables as/if needed.
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

**Note:** The following demo commands are for an **Indy-based** credential ecosystem. The application defaults to the `indy` proof format, so these examples work out-of-the-box. You can switch to `anoncreds` by setting the `ACAPY_PROOF_FORMAT` environment variable.

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
            "schema_name": "Person"
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

## Advanced Features

### Prover Role (Trusted Verifier Credentials)

VC-AuthN can also act as a **prover**, holding credentials in its own wallet and responding to proof requests from external verifiers. This is useful for trusted verifier networks where VC-AuthN must prove its authorization status.

For detailed information about prover-role functionality, testing, and configuration, see the [Prover Role Logging documentation](docs/ProverRoleLogging.md).

**Quick Test**: To test prover-role functionality with the bootstrap script:
```bash
cd docker
TEST_PROVER_ROLE=true \
LEDGER_URL=http://test.bcovrin.vonx.io \
TAILS_SERVER_URL=https://tails-test.vonx.io \
./manage bootstrap
```

## Debugging

To connect a debugger to the `vc-authn` controller service, start the project using `DEBUGGER=true ./manage single-pod` and then launch the debugger.

### Finding the Debugger Port

When using `DEBUGGER=true`, the debugger port is dynamically assigned from the range 5678-5688 to avoid conflicts between replicas.

To find the actual debugger port:
```bash
# Start with debugger enabled (use single-pod for debugging)
DEBUGGER=true ./manage single-pod

# Find the assigned port
docker ps | grep controller
# Look for port mapping like: 0.0.0.0:5679->5678/tcp
# Connect your debugger to the host port (5679 in this example)
```

**Example output:**
```
CONTAINER ID   IMAGE                              PORTS
abc123def456   acapy-vc-authn-oidc-controller    0.0.0.0:5679->5678/tcp
```

In this example, connect your debugger to `localhost:5679`.

### VSCode Configuration

This is a sample debugger launch configuration for VSCode that can be used by adding it to `launch.json`, it assumes a `.venv` folder containing the virtual environment was created in the repository root. **Note:** Update the `port` value to match the discovered port from the `docker ps` command above.

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
