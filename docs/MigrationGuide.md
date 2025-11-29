# ACAPy VC-AuthN Migration Guide

This document contains instructions and tips useful when upgrading ACAPy VC-AuthN.

## 1.x -> 2.x

The functionality has mostly remained unchanged, however there are some details that need to be accounted for.

* Endpoints: `authorization` and `token` endpoints have changed, review the new values by navigating to the `.well-known` URL and update your integration accordingly.

* Proof configurations: to be moved to a `v2.0` instance, the following changes need to happen in existing proof-configurations.
  - The `name` identifier for disclosed attributes has been deprecated, use the `names` array instead.
  - If backwards-compatibility with `v1.0` tokens is required, the `include_v1_attributes` flag should be switched to `true` (see the [configuration guide](./ConfigurationGuide.md)).

* Client Types: ACAPy VC-AuthN 2.0 currently only supports confidential clients using client id/secret. If public clients were previously registered, they will now need to use an AIM (e.g.: keycloak) as broker.

## For versions after 2.3.2

### Multi-Tenant Webhook Configuration
If you are running in Multi-Tenant mode (`ACAPY_TENANCY="multi"`), you **must** now define the `CONTROLLER_WEB_HOOK_URL` environment variable.

*   **Why:** The controller now explicitly registers this URL with the specific ACA-Py tenant wallet on startup. This fixes issues where OIDC authentication flows would hang because the agent sent verifications to the wrong location or failed authentication.
*   **Action Required:** Update your `docker-compose` or Kubernetes config:
    ```yaml
    environment:
      - CONTROLLER_WEB_HOOK_URL=https://<your-controller-domain>/webhooks
    ```

### New Tenancy Mode: Traction

A new mode has been added for integrating with Traction (or secured multi-tenant agents where Admin APIs are blocked).

*   **Setting:** `ACAPY_TENANCY="traction"`
*   **Requirements:** Requires `TRACTION_TENANT_ID` and `TRACTION_TENANT_API_KEY`.
*   **Behavior:** Authenticates directly with the Tenant API and bypasses `multitenancy/wallet` Admin endpoints.