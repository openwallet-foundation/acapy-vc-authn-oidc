# Prover Role Logging

This document describes the prover role logging functionality added in [PR #928](https://github.com/openwallet-foundation/acapy-vc-authn-oidc/pull/928)

## Overview

VC-AuthN OIDC typically acts as a **verifier**, requesting and
verifying credentials from users. In some scenarios, VC-AuthN can also
act as a **prover**, responding to proof requests from external
verifiers with credentials it holds in its own wallet.

This feature adds structured logging when VC-AuthN receives
`present_proof_v2_0` webhooks where it is acting as the prover,
ensuring these events are properly logged and do not interfere with
the standard verifier-role authentication flows.

## Dual Role Architecture

### Verifier Role (Primary)

In its primary role, VC-AuthN:
- Receives authentication requests from OIDC clients
- Creates proof requests for users
- Verifies presentations from users' wallets
- Issues OIDC tokens upon successful verification

### Prover Role (Secondary)

When acting as a prover, VC-AuthN:
- Holds credentials in its own wallet
- Responds to proof requests from external verifiers
- Presents credentials without triggering OIDC authentication flows

This is useful for trusted verifier networks where VC-AuthN must prove its authorization status to external systems.

## Use Cases

### Trusted Verifier Credentials

The primary use case is for trusted verifier networks:

1. A governance authority issues "trusted verifier" credentials to authorized VC-AuthN instances
2. Other systems can verify that a VC-AuthN instance is authorized before accepting its verification results
3. VC-AuthN holds these credentials in its wallet and presents them when challenged

**Example Flow:**
```
1. Governance Authority → Issues "Trusted Verifier Credential" → VC-AuthN Wallet
2. External System → Requests proof of "Trusted Verifier Credential" → VC-AuthN
3. VC-AuthN → Presents credential from wallet → External System
4. External System → Verifies VC-AuthN is authorized verifier
```

### Multi-Agent Architectures

Organizations may deploy multiple specialized agents where:
- VC-AuthN holds organizational credentials
- External systems request organizational proofs
- VC-AuthN responds on behalf of the organization

## Implementation Details

### Webhook Handling Logic

When ACA-Py sends a `present_proof_v2_0` webhook to VC-AuthN, the handler checks the `role` field:

```python
# Check for prover-role (issue #898)
role = webhook_body.get("role")

if role == "prover":
    # Handle prover-role separately - VC-AuthN is responding to a proof request
    pres_ex_id = webhook_body.get("pres_ex_id")
    connection_id = webhook_body.get("connection_id")
    state = webhook_body.get("state")

    logger.info(
        f"Prover-role webhook received: {state}",
        pres_ex_id=pres_ex_id,
        connection_id=connection_id,
        role=role,
        state=state,
        timestamp=datetime.now(UTC).isoformat(),
    )

    # Return early - do NOT trigger verifier-role logic or cleanup
    return {"status": "prover-role event logged"}
```

**Key behaviors:**
- **Early return**: Prevents verifier logic from executing
- **Structured logging**: Records all relevant details with timestamps
- **No cleanup**: Prover-role presentations are managed by the external verifier
- **No auth session lookup**: These presentations aren't tied to OIDC authentication flows

### Files Modified

| File                                                      | Changes                                                            |
|-----------------------------------------------------------|--------------------------------------------------------------------|
| `oidc-controller/api/routers/acapy_handler.py`            | Added prover-role detection and logging logic                      |
| `oidc-controller/api/routers/tests/test_acapy_handler.py` | Added comprehensive test suite for prover-role webhooks            |
| `scripts/bootstrap-trusted-verifier.py`                   | Added prover-role testing capability                               |
| `docker/docker-compose.yaml`                              | Added `ACAPY_AUTO_RESPOND_PRESENTATION_REQUEST=true` configuration |
| `docker/docker-compose-issuer.yaml`                       | Added `ACAPY_AUTO_RESPOND_PRESENTATION_REQUEST=true` configuration |

## Testing the Prover Role

### Bootstrap Script

The `scripts/bootstrap-trusted-verifier.py` script provides end-to-end testing of the prover-role functionality:

1. **Credential Issuance** - Issues a "trusted verifier" credential to VC-AuthN
2. **Prover Role Testing** - Sends a proof request to VC-AuthN and verifies the response
3. **Logging Verification** - Allows inspection of prover-role webhook logs

### Running the Test

From the `docker/` directory, run:

```bash
TEST_PROVER_ROLE=true \
./manage bootstrap
```

### Test Flow

When `TEST_PROVER_ROLE=true`, the bootstrap script executes the following phases:

#### 1. Setup Phase
- Waits for issuer and verifier agents to be ready
- Registers public DID on BCovrin Test ledger
- Creates schema and credential definition
- Creates connection between issuer and VC-AuthN

#### 2. Issuance Phase
- Issues trusted verifier credential to VC-AuthN
- Verifies credential is stored in VC-AuthN's wallet

#### 3. Prover Role Test Phase
- Sends proof request from issuer to VC-AuthN
- VC-AuthN automatically responds with presentation (via ACA-Py auto-respond configuration)
- Verifies presentation is verified successfully
- Logs confirmation message

### Expected Output

Successful test output:
```
============================================================
PROVER-ROLE TEST: Starting (issue #898)
============================================================
PROVER-ROLE TEST: Sending proof request to VC-AuthN...
PROVER-ROLE TEST: Sent proof request (pres_ex_id: <id>)
PROVER-ROLE TEST: Waiting for VC-AuthN to respond with presentation...
PROVER-ROLE TEST: Presentation state: done, verified: true (attempt N)
PROVER-ROLE TEST: ✓ Presentation verified successfully!
============================================================
PROVER-ROLE TEST: ✓ SUCCESS
Check controller logs for prover-role webhook events with role='prover'
============================================================
```

### Verifying Logs

Check controller logs for prover-role webhook events:

```bash
./manage logs controller | grep -i "prover-role"
```

Expected log entries:
```
Prover-role webhook received: presentation-sent
pres_ex_id: <id>
connection_id: <id>
role: prover
state: presentation-sent
timestamp: 2024-01-01T12:00:00.000000Z
```

## Configuration

### Environment Variables

The following environment variables are used by the bootstrap script to configure the prover-role testing:

| Variable                     | Type   | Default                                                  | Description                                    |
|------------------------------|--------|----------------------------------------------------------|------------------------------------------------|
| `TEST_PROVER_ROLE`           | bool   | `false`                                                  | Enable prover-role testing in bootstrap script |
| `ISSUER_ADMIN_URL`           | string | `http://localhost:8078`                                  | Issuer agent admin API URL                     |
| `VERIFIER_ADMIN_URL`         | string | `http://localhost:8077`                                  | Verifier (VC-AuthN) agent admin API URL        |
| `VERIFIER_ADMIN_API_KEY`     | string | (empty)                                                  | API key for verifier agent                     |
| `VERIFIER_SCHEMA_NAME`       | string | `verifier_schema<random>`                                | Schema name for trusted verifier credentials   |
| `VERIFIER_SCHEMA_VERSION`    | string | `1.0`                                                    | Schema version                                 |
| `VERIFIER_SCHEMA_ATTRIBUTES` | string | `verifier_name,authorized_scopes,issue_date,issuer_name` | Comma-separated credential attributes          |
| `VERIFIER_NAME`              | string | `Trusted Verifier`                                       | Name of the verifier instance                  |
| `AUTHORIZED_SCOPES`          | string | `default_scope`                                          | Comma-separated authorized scopes              |
| `ISSUER_NAME`                | string | `Trusted Verifier Issuer`                                | Name of the issuing authority                  |

### Customizing Credential Values

You can customize the credential values issued to VC-AuthN by setting environment variables:

```bash
VERIFIER_NAME="My VC-AuthN Instance"
AUTHORIZED_SCOPES="health,education,finance"
ISSUER_NAME="Government Authority"
```

## Monitoring and Operations

### Log Analysis

Prover-role events are logged with structured data. When `LOG_WITH_JSON=TRUE`, logs appear as:

```json
{
  "event": "prover-role webhook received",
  "pres_ex_id": "uuid",
  "connection_id": "uuid",
  "role": "prover",
  "state": "presentation-sent",
  "timestamp": "2024-01-01T12:00:00.000000Z"
}
```

When `LOG_WITH_JSON=FALSE`, logs are formatted as:

```
Prover-role webhook received: presentation-sent
pres_ex_id: uuid
connection_id: uuid
role: prover
state: presentation-sent
timestamp: 2024-01-01T12:00:00.000000Z
```

### Presentation States

When VC-AuthN acts as prover, the following states are expected:

| State               | Description                          |
|---------------------|--------------------------------------|
| `request-received`  | External verifier sent proof request |
| `presentation-sent` | VC-AuthN sent presentation           |
| `done`              | Presentation exchange completed      |
| `abandoned`         | Exchange was abandoned               |

### Troubleshooting

#### No prover-role logs appearing

- Verify VC-AuthN has credentials in its wallet: `GET /credentials`
- Check that external verifier is sending valid proof requests
- Ensure connection is established between verifier and VC-AuthN
- Verify `ACAPY_AUTO_RESPOND_PRESENTATION_REQUEST=true` is configured

#### Presentation fails verification

- Verify credential definition matches proof request restrictions
- Check that credential attributes satisfy requested predicates
- Ensure credential hasn't been revoked (if revocation is enabled)

#### Bootstrap script fails

- Verify all agents are running: `docker ps`
- Check ledger connectivity: `curl http://test.bcovrin.vonx.io/status`
- Review issuer agent logs: `./manage logs issuer`
- Ensure required environment variables are set

## Architecture Considerations

### No Auth Session Coupling

Prover-role presentations are **not** coupled to OIDC authentication sessions. This design is intentional because:

- Prover-role activities are organizational/agent-level, not user-level
- No associated auth sessions are created in MongoDB
- No OIDC token issuance is triggered
- User authentication flows remain unaffected

### No Cleanup Required

Unlike verifier-role flows, prover-role presentations don't require cleanup because:

- The external verifier manages the presentation lifecycle
- VC-AuthN doesn't maintain presentation records
- Connection management is handled by standard ACA-Py logic

### Auto-Response Configuration

For prover-role to work automatically, ACA-Py must be configured with the following flag:

```yaml
environment:
  - ACAPY_AUTO_RESPOND_PRESENTATION_REQUEST=true
```

Or via command-line arguments:
```bash
--auto-respond-presentation-request
```

**Note:** Auto-response is typically enabled in development/testing environments. Production deployments may require manual approval workflows for security purposes.

## Test Coverage

The test suite in `oidc-controller/api/routers/tests/test_acapy_handler.py` provides comprehensive coverage of prover-role functionality:

### Test Cases

1. **Basic Prover Role Detection**
   - Webhooks with `role="prover"` trigger logging and early return
   - Auth session lookup is NOT performed
   - Verifier logic is NOT executed

2. **Multiple Presentation States**
   - Tests all presentation states: `request-sent`, `presentation-sent`, `done`, `abandoned`
   - Verifies consistent behavior across states

3. **Role Disambiguation**
   - Missing `role` field defaults to verifier behavior
   - Explicit `role="verifier"` triggers verifier logic
   - Only `role="prover"` triggers prover-specific handling

4. **Missing Field Handling**
   - Gracefully handles missing optional fields (`connection_id`, `state`)
   - Logs available information without crashing

5. **Verifier Logic Preservation**
   - Ensures verifier-role webhooks still work correctly
   - No regression in primary functionality

### Running Tests

To run the prover-role test suite:

```bash
cd oidc-controller
poetry run pytest api/routers/tests/test_acapy_handler.py::TestProverRoleWebhooks -v
```

## Security Considerations

### Credential Access Control

When VC-AuthN acts as prover, the following access controls apply:

- Only responds to proof requests for credentials it holds
- Cannot present credentials it doesn't possess
- Respects credential restrictions and predicates defined in proof requests

### Network Boundaries

In production deployments, consider the following security measures:

- Implement firewall rules limiting which systems can request proofs from VC-AuthN
- Use connection-based verification to establish trust before accepting proof requests
- Monitor prover-role activity for unexpected or unauthorized proof requests
- Review and approve connection invitations before establishing connections

### Audit Trail

All prover-role activities are logged with the following information:

- Presentation exchange IDs for correlation
- Connection IDs for tracking external verifiers
- Timestamps for audit trails
- State transitions for debugging and compliance

## Future Enhancements

Potential improvements to prover-role functionality include:

1. **Manual Approval Workflows** - Add UI for approving proof requests before responding
2. **Policy-Based Responses** - Configure which credentials can be shared with which verifiers
3. **Metrics and Dashboards** - Track prover-role activity over time
4. **Notification System** - Alert administrators of incoming proof requests
5. **Connection Trust Management** - Whitelist/blacklist external verifiers
6. **Advanced Audit Reporting** - Generate compliance reports for prover-role activities

## Related Documentation

- [Configuration Guide](./ConfigurationGuide.md) - General configuration options
- [Best Practices](./BestPractices.md) - Security and operational best practices
- [README](./README.md) - Project overview and architecture

## References

- **GitHub Issue**: [#898 - Enhance logging for prover-role](https://github.com/openwallet-foundation/acapy-vc-authn-oidc/issues/898)
- **Pull Request**: [#928 - Logging for prover role](https://github.com/openwallet-foundation/acapy-vc-authn-oidc/pull/928)
- **Bootstrap Script**: [PR #917 - Bootstrap script for trusted verifier credentials](https://github.com/openwallet-foundation/acapy-vc-authn-oidc/pull/917)

## Support

For questions or issues:
- Open an issue on [GitHub](https://github.com/openwallet-foundation/acapy-vc-authn-oidc/issues)
- Review existing discussions in issue #898
- Contact the maintainers via the OpenWallet Foundation
