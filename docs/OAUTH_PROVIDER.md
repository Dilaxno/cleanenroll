# CleanEnroll OAuth 2.0 Provider

This document describes the OAuth 2.0 provider implementation for CleanEnroll, enabling third-party applications to securely access user data.

## Overview

CleanEnroll implements a full OAuth 2.0 authorization server following RFC 6749, with support for:
- Authorization Code Grant with PKCE (RFC 7636)
- Refresh Token Grant
- Token Revocation (RFC 7009)
- Token Introspection (RFC 7662)
- Signed Webhooks for real-time events

## Endpoints

### Authorization Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/oauth/authorize` | GET | Authorization endpoint - initiates OAuth flow |
| `/oauth/authorize/consent` | POST | Handle user consent decision |
| `/oauth/token` | POST | Token endpoint - exchange code for tokens |
| `/oauth/revoke` | POST | Revoke access or refresh tokens |
| `/oauth/introspect` | POST | Introspect token validity |

### Client Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/developer/oauth/clients` | POST | Create OAuth client |
| `/api/developer/oauth/clients` | GET | List OAuth clients |
| `/api/developer/oauth/clients/{client_id}` | GET | Get client details |
| `/api/developer/oauth/clients/{client_id}` | PATCH | Update client |
| `/api/developer/oauth/clients/{client_id}` | DELETE | Delete client |
| `/api/developer/oauth/clients/{client_id}/rotate-secret` | POST | Rotate client secret |

### Protected API (v2)

| Endpoint | Method | Scope Required |
|----------|--------|----------------|
| `/api/v2/forms` | GET | `forms:read` |
| `/api/v2/forms/{form_id}` | GET | `forms:read` |
| `/api/v2/forms/{form_id}/submissions` | GET | `submissions:read` |
| `/api/v2/submissions/{submission_id}` | GET | `submissions:read` |
| `/api/v2/forms/{form_id}/analytics` | GET | `analytics:read` |
| `/api/v2/payments` | GET | `payments:read` |
| `/api/v2/me` | GET | `profile:read` |


### Webhook Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/developer/oauth/clients/{client_id}/webhook` | POST | Register webhook |
| `/api/developer/oauth/clients/{client_id}/webhook` | GET | Get webhook config |
| `/api/developer/oauth/clients/{client_id}/webhook` | DELETE | Remove webhook |
| `/api/developer/oauth/clients/{client_id}/webhook/events` | GET | List webhook events |
| `/api/developer/oauth/clients/{client_id}/webhook/events/{event_id}/retry` | POST | Retry failed event |
| `/api/developer/oauth/clients/{client_id}/webhook/test` | POST | Send test webhook |

## Available Scopes

| Scope | Description |
|-------|-------------|
| `forms:read` | View forms and configurations |
| `forms:write` | Create, update, delete forms |
| `submissions:read` | View form submissions |
| `submissions:write` | Create and manage submissions |
| `analytics:read` | View form analytics |
| `payments:read` | View payment information |
| `webhooks:manage` | Manage webhook configurations |
| `profile:read` | View basic profile information |

## Authorization Flow

### 1. Create OAuth Client

```bash
curl -X POST https://api.cleanenroll.com/api/developer/oauth/clients \
  -H "Authorization: Bearer <firebase_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My App",
    "redirect_uris": ["https://myapp.com/callback"],
    "allowed_scopes": ["forms:read", "submissions:read"]
  }'
```

Response includes `client_id` and `client_secret` (shown only once).

### 2. Redirect User to Authorization

```
https://api.cleanenroll.com/oauth/authorize?
  response_type=code&
  client_id=ce_xxx&
  redirect_uri=https://myapp.com/callback&
  scope=forms:read%20submissions:read&
  state=random_state_value&
  code_challenge=xxx&
  code_challenge_method=S256
```

### 3. Exchange Code for Tokens

```bash
curl -X POST https://api.cleanenroll.com/oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=<authorization_code>" \
  -d "redirect_uri=https://myapp.com/callback" \
  -d "client_id=ce_xxx" \
  -d "client_secret=ces_xxx" \
  -d "code_verifier=<pkce_verifier>"
```

Response:
```json
{
  "access_token": "ceat_xxx",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "cert_xxx",
  "scope": "forms:read submissions:read"
}
```

### 4. Access Protected Resources

```bash
curl https://api.cleanenroll.com/api/v2/forms \
  -H "Authorization: Bearer ceat_xxx"
```

### 5. Refresh Access Token

```bash
curl -X POST https://api.cleanenroll.com/oauth/token \
  -d "grant_type=refresh_token" \
  -d "refresh_token=cert_xxx" \
  -d "client_id=ce_xxx" \
  -d "client_secret=ces_xxx"
```

## Webhook Events

### Event Types

| Event | Description |
|-------|-------------|
| `submission.created` | New form submission received |
| `payment.succeeded` | Payment completed successfully |
| `form.updated` | Form configuration changed |
| `form.published` | Form published |
| `form.deleted` | Form deleted |

### Webhook Payload

```json
{
  "id": "evt_xxx",
  "event": "submission.created",
  "created_at": "2024-01-15T10:30:00Z",
  "data": {
    "submission_id": "sub_xxx",
    "form_id": "form_xxx",
    "fields": {...}
  }
}
```

### Signature Verification

Webhooks include `X-CleanEnroll-Signature` header:

```
t=1705312200,v1=5257a869e7ecebeda32affa62cdca3fa51cad7e77a0e56ff536d0ce8e108d8bd
```

Verify using HMAC-SHA256:
```python
import hmac
import hashlib

def verify_signature(payload: str, signature: str, secret: str) -> bool:
    parts = dict(p.split("=") for p in signature.split(","))
    timestamp = parts["t"]
    expected_sig = parts["v1"]
    
    signed_payload = f"{timestamp}.{payload}"
    computed = hmac.new(
        secret.encode(),
        signed_payload.encode(),
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(computed, expected_sig)
```

## Token Lifetimes

| Token Type | Lifetime |
|------------|----------|
| Authorization Code | 10 minutes |
| Access Token | 1 hour |
| Refresh Token | 30 days |

## Database Schema

Run the migration to create OAuth tables:

```bash
psql -d cleanenroll -f backend/db/oauth_schema.sql
```

## Security Best Practices

1. **Always use HTTPS** for redirect URIs (except localhost)
2. **Use PKCE** for public clients (mobile/SPA apps)
3. **Store client secrets securely** - they're only shown once
4. **Verify webhook signatures** before processing events
5. **Implement token refresh** before access tokens expire
6. **Revoke tokens** when users disconnect your app
