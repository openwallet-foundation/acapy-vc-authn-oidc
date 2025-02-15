# Configuration Guide

## Using an Access and Identity Management Broker

### Adding VC Authn as Identity Provider

The first step is to add VC Authn as a new Identity Provider for our AIM system. The following instructions are built for Keycloak, but should be applicable for any AIM that supports Open ID Connect.

1. Click on the **Identity Providers** tab and select **Open ID Connect v1.0** from the **User-defined** section.
   ![vc-authn-oidc-flow](img/01-new-idp.png)

2. In the next page, select an alias and a display name for your Idp. The alias will be used to generate a unique URL corresponding to the new provider, while the display name will be used in the Keycloak login screen on the button corresponding to the IdP.
   ![vc-authn-oidc-flow](img/02-settings-1.png)

3. We will now configure the Open Id Connect parameters for our new provider.

[!NOTE]
ACAPy VC-AuthN exposes the `.well-known/openid-configuration` endpoint to provide systems that support it automatic discovery of the endpoints and features of the Identity Provider. If you decide to do so, switch on **Use discovery endpoint** and enter `{VC_AUTHN_PUBLIC_URL}/.well-known/openid-configuration` to proceed.

To input settings manually, or review them:

- **Authorization URL**: this must be set to `{PUBLIC_VC_AUTHN_URL}/authorize`

- **Token URL**: this must be set to `{PUBLIC_VC_AUTHN_URL}/token`

- **Disable User Info**: it is recommended to disable the user info endpoint, since VC Authn does not store/provide user information.

- **Client ID/Client Secret**: these settings will be used to identify and secure the IdP integration between Keycloak and VC Authn. Make sure the **client secret** parameter is unique to your VC Authn instance. ACAPy VC-AuthN supports two methods of client authentication: `Client secret sent as basic auth` and `Client secret sent as post`.

- **Default Scopes**: this must be set to `vc_authn` to instruct the AIM broker which scopes to request from the IdP.

- **Validate Signatures**: if you want to have the signature of ACAPy VC-AuthN validated by Keycloak, turn this on, flip the `Use JWKS URL` to true and set `JWKS URL` to `{PUBLIC_VC_AUTHN_URL}/.well-known/openid-configuration/jwks`.

- **Forwarded Query Parameters**: set this to `pres_req_conf_id`. This parameter is used by VC Authn to lookup in its database the configuration to generate presentation request to be displayed to the user and the AIM system needs to forward it when initiating the authentication.

![vc-authn-oidc-flow](img/02-settings-2.png)

Save the settings and take note of the generated **Redirect URI** and **Client ID/Secret** parameters, they will be used in the next steps.

### Configuring VC Authn

ACAPy VC-AuthN can be configured by using the API endpoints exposed on Swagger at `VC_AUTHN_PUBLIC_URL}/docs`. The `oidc_clients` namespace provides RESTful APIs to create/delete/update clients.

To register a new client, `POST` a request to the `/clients` endpoint with a payload containing the client id/secret and redirect URL noted at the previous step. Example:

```json
{
  "client_id": "my-new-client",
  "client_name": "my-keycloak",
  "client_secret": "super-secret",
  "response_types": ["code", "id_token", "token"],
  "token_endpoint_auth_method": "client_secret_post",
  "redirect_uris": [
    "http://localhost:8880/auth/realms/vc-authn/broker/vc-authn/endpoint"
  ]
}
```

### Mappers

Once the new Identity Provider is configured, mappers should be added in order to consume the claims in issued tokens. This can be done by clicking `Add mapper` in the `Mappers` tab within the Identity Provider configuration view. Mappers should be configured using the type `Attribute Importer` and, at minimum, should include:

- `pres_req_conf_id`: this will return the id of the proof request configuration that was used during the authentication request. It should be used by the client application to check authentication was completed by using the expected credential (see [best practices](./BestPractices.md) for additional information).
- `vc_presented_attributes`: this will contain a serialized JSON object containing all of the attributes requested as part of the proof request, for the application to consume. If individual mappers are preferred, they can be configured to extract individual claims.

The following is an example mapper configuration:
![vc-authn-oidc-flow](img/03-mappers.png)

## Direct Configuration

ACAPy VC-AuthN 2.0 only supports confidential clients, and cannot be configured to be invoked directly from Single-Page applications. For back-end systems, however, the above instructions should still apply.

## Environment Variables

Several functions in ACAPy VC-AuthN can be tweaked by using the following environment variables.

| Variable                  | Type                                   | What it does                                                                                                                                                                                                                                                                                                                                                                                                                                           | NOTES                                                                                                                                   |
| ------------------------- | -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------- |
| SET_NON_REVOKED           | bool                                   | if True, the `non_revoked` attributed will be added to each of the present-proof request `requested_attribute` and `requested_predicate` with 'from=0' and'to=`int(time.time())`                                                                                                                                                                                                                                                                       |                                                                                                                                         |
| USE_OOB_PRESENT_PROOF     | bool                                   | if True, the present-proof request will be provided as a an [out of band](https://github.com/hyperledger/aries-rfcs/tree/main/features/0434-outofband) invitation with a [present-proof](https://github.com/hyperledger/aries-rfcs/tree/main/features/0037-present-proof) request inside. If False, the present-proof request will be use the [service-decorator](https://github.com/hyperledger/aries-rfcs/tree/main/features/0056-service-decorator) | **TRUE:** BC Wallet supports our OOB Message, BiFold, Lissi, Trinsic, and Estatus all read the QR code as 'Invalid' |
| USE_OOB_LOCAL_DID_SERVICE | bool                                   | Instructs ACAPy VC-AuthN to use a local DID, it must be used when the agent service is not registered on the ledger with a public DID                                                                                                                                                                                                                                                                                                                        | Use this when `ACAPY_WALLET_LOCAL_DID` is set to `true` in the agent.                                                                   |
| USE_URL_DEEP_LINK         | bool                                   | If True, in Mobile mode the BC Wallet deep link will use an encoded URL (`WALLET_DEEP_LINK_PREFIX?_url={redirect URL}`), otherwise will use the encoded connection invitation (`{WALLET_DEEP_LINK_PREFIX}?c_i={connection invitation payload}`)                                                                                                                                                                                                        | Default False/.. To control using the `?_url` handler                                                                                   |
| WALLET_DEEP_LINK_PREFIX   | string                                 | Custom URI scheme and host to use for deep links (e.g. `{WALLET_DEEP_LINK_PREFIX}?c_i={connection invitation payload`)                                                                                                                                                                                                                                                                                                                                 | Default bcwallet://aries_proof-request                                                                                                  |
| LOG_WITH_JSON             | bool                                   | If True, logging output should printed as JSON if False it will be pretty printed.                                                                                                                                                                                                                                                                                                                                                                     | Default behavior will print as JSON.                                                                                                    |
| LOG_TIMESTAMP_FORMAT      | string                                 | determines the timestamp formatting used in logs                                                                                                                                                                                                                                                                                                                                                                                                       | Default is "iso"                                                                                                                        |
| LOG_LEVEL                 | "DEBUG", "INFO", "WARNING", or "ERROR" | sets the minimum log level that will be printed to standard out                                                                                                                                                                                                                                                                                                                                                                                        | Defaults to DEBUG                                                                                                                       |

## Proof Request Configuration Options

The basic structure of a proof-request configuration is described [here](README.md#data-model). Additional options are described via the Swagger document, and listed below:

- `include_v1_attributes`: defaults to `false`, switch to `true` if root-level claims as presented in ACAPy VC-AuthN v1 are still required for the proof-request.

### Proof Substitution Variables

Proof Request configurations (as described [here](README.md#data-model)) are pre-set records stored in the ACAPy VC-AuthN database comprising of the details to make the proof request from.
At runtime when the user is directed to the proof challenge, the appropriate configuration is fetched and the proof request built from that.  
In certain use cases you may want the proof request to have a specific value in the proof (probably in a requested predicate) generated at that moment rather than preset. 

An example could be using today's date, a "right now" timestamp, or an age-check (IE today's date minus 19 years).  
To accomodate this, ACAPy VC-AuthN **proof substitution variables** can be used as placeholders in the configurations. They can just be added as string in the configuration with a `$` prefix.
There are a handful of built-in options:

| Substitution Variable     | Details                                                                                   |
| ------------------------- | ----------------------------------------------------------------------------------------- |
| $now                      | Inserts the current timestamp in seconds since the epoch as an int                        |
| $today_int                | Inserts Today's date in YYYYMMDD format as an int                                         |
| $tomorrow_int             | Inserts Tomorrow's date in YYYYMMDD format as an int                                      |
| $threshold_years_X        | Supply a number for X. Inserts today's date minus X years in YYYYMMDD format as an int    |

`$threshold_years_X` is an example of a 'dynamic' substitution variable where part of the variable name can act as a parameter

So in a proof request config a requested predicate could have
```
          "p_value": "$today_int",
          "p_type": ">"
```
and at runtime when the user navigates to the QR code page, the proof would include something like
```
          "p_value": 20240927,
          "p_type": ">"
```


See the `oidc-controller\api\verificationConfigs\variableSubstitutions.py` file for implementations.

#### Customizing variables
For user defined variable substitutions users can set the environment
variable to point at a python file defining new substitutions.

##### User Defined Variable API
In `oidc-controller\api\verificationConfigs\variableSubstitutions.py`
you will find the method `add_variable_substitution` which can be used
to modify the existing instance of `VariableSubstitutionMap` named
`variable_substitution_map`.

Takes a valid regular expression `pattern` and a function who's
arguments correspond with each regex group `substitution_function`. Each
captured regex group will be passed to the function as a `str`.

Here is an example python file that would define a new variable
substitution `$today_plus_x_times_y` which will add X days multiplied
by Y days to today's date

```python
from datetime import datetime, timedelta

def today_plus_times(added_days: str, multiplied_days: str) -> int:
	return int(
		((datetime.today() + timedelta(days=int(added_days))) * timedelta(days=int(multiplied_days)))
	).strftime("%Y%m%d"))

# variable_substitution_map will already be defined in variableSubstitutions.py
variable_substitution_map.add_variable_substitution(r"\$today_plus_(\d+)_times_(\d+)", today_plus_times)
```

For an example of this python file see `docker/oidc-controller/config/user_variable_substitution_example.py`

All that is necessary is the adding of substitution variables.These
changes will be applied by ACAPy VC-AuthN during startup. The variable
`variable_substitution_map` **will already be defined**.

After loading the python file during the service startup each new user
defined variable is logged for confirmation. Any failures to load
these changes will be logged. If no new definitions are found
indication of this will also be logged

# User Customized QR Page

## ConfigMap Based Overrides

By default the QR page shown to users uses OpenWallet branding users
are capable of overriding any of these files using the
`controller.htmlFileOverrides` value in
[values.yaml](charts/vc-authn-oidc/values.yaml).
These files will override the existing files seen in
[html-templates](../html-templates/).

## Complete Directory Overrides

In addition, to allow for more flexibility users are welcome to build
an image based on `ghcr.io/openwallet-foundation/acapy-vc-authn-oidc`
mounting their complete directory with new assets.

To inform the oidc controller of this new directory update
[.Values.controller.templateDirectory](../charts/vc-authn-oidc/values.yaml)
to the location of this new directory

## HTML Template Formats

The HTML templates use [Jinja2](https://pypi.org/project/Jinja2/) to
insert the necessary information from the oidc controller.

The provided template sections are

- image_contents: a base64 encoded image used as the QR code
- url_to_message: URL the QR code points to
- callback_url: URL used when verification is complete
- pres_exch_id: id of the presentation exchange for this authsession
- pid: auth_session id 
- controller_host: URL pointing to this controller
- challenge_poll_uri: URL used for polling the authsessions state
- wallet_deep_link: deep link used to integrate with bcwallet for mobile users
- title: Title of the current proof request
- claims: List of claims requested in this proof request

For more information please see
- [oidc.py](../oidc-controller/api/routers/oidc.py) and
- [verified_credentials.html](../html-templates/verified_credentials.html)
- [wallet_howto.html](../html-templates/wallet_howto.html)
- [ver_config_explorer.html](../html-templates/ver_config_explorer.html)
