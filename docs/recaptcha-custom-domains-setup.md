# Domain-Specific reCAPTCHA Setup Guide

## Overview

CleanEnroll now supports automatic provisioning of domain-specific reCAPTCHA keys for custom domains. This solves the "Invalid domain for site key" error that occurs when users embed forms on their custom domains.

## How It Works

1. **Automatic Provisioning**: When a user verifies their custom domain, the system automatically creates a new reCAPTCHA v2 site key specifically for that domain using the Google reCAPTCHA Admin API.

2. **Secure Storage**: The site key (public) and secret key (encrypted) are stored in the database per form.

3. **Dynamic Injection**: When a form is loaded on a custom domain, the domain-specific site key is injected into the frontend.

4. **Verification**: Form submissions use the domain-specific secret key to verify reCAPTCHA tokens.

## Required Environment Variables

Add these to your `.env` file:

```bash
# Google reCAPTCHA Admin API Configuration
RECAPTCHA_ADMIN_API_KEY=your_google_cloud_api_key_here
RECAPTCHA_PROJECT_ID=your_google_cloud_project_id_here

# Encryption key for storing reCAPTCHA secrets (32 url-safe base64-encoded bytes)
# Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
RECAPTCHA_ENCRYPTION_KEY=your_32_byte_base64_key_here

# Legacy global reCAPTCHA keys (fallback for main domain)
RECAPTCHA_SECRET_KEY=your_legacy_secret_key_here
```

## Setup Instructions

### 1. Enable reCAPTCHA Enterprise API

1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Select your project or create a new one
3. Enable **reCAPTCHA Enterprise API**
4. Note your Project ID

### 2. Create API Key

1. Navigate to **APIs & Services** > **Credentials**
2. Click **Create Credentials** > **API Key**
3. Restrict the API key to only **reCAPTCHA Enterprise API**
4. Copy the API key to `RECAPTCHA_ADMIN_API_KEY`

### 3. Generate Encryption Key

Run this command to generate a secure encryption key:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Add the output to `RECAPTCHA_ENCRYPTION_KEY` in your `.env` file.

### 4. Run Database Migration

Execute the migration to add reCAPTCHA key columns:

```sql
psql $DATABASE_URL < backend/db/migrations/20251109_add_recaptcha_keys_per_domain.sql
```

Or run it via your migration tool:

```bash
cd backend
python -c "
from db.database import async_session_maker
import asyncio
from sqlalchemy import text

async def migrate():
    async with async_session_maker() as session:
        with open('db/migrations/20251109_add_recaptcha_keys_per_domain.sql') as f:
            await session.execute(text(f.read()))
        await session.commit()

asyncio.run(migrate())
"
```

### 5. Install Required Python Dependencies

```bash
pip install cryptography httpx
```

## Database Schema

New columns added to `forms` table:

- `recaptcha_site_key` (VARCHAR(255)) - Public site key for the custom domain
- `recaptcha_secret_key` (VARCHAR(255)) - Encrypted secret key for verification
- `recaptcha_key_created_at` (TIMESTAMP) - When keys were provisioned

## API Flow

### Custom Domain Verification

```
POST /forms/{form_id}/custom-domain/verify
Body: { "customDomain": "forms.example.com" }

Response:
{
  "verified": true,
  "domain": "forms.example.com",
  "sslVerified": true,
  "recaptchaProvisioned": true,  // ← New field
  "message": "Domain verified and ready..."
}
```

### Form Retrieval (includes site key)

```
GET /forms/{form_id}

Response includes:
{
  "id": "abc123",
  "recaptchaEnabled": true,
  "recaptchaSiteKey": "6Lc...",  // ← Domain-specific site key
  "customDomain": "forms.example.com",
  ...
}
```

## Frontend Integration

The frontend automatically uses the domain-specific site key when available:

```javascript
// In FormViewPage.jsx or form embed
const siteKey = form.recaptchaSiteKey || FALLBACK_SITE_KEY;

<ReCAPTCHA
  sitekey={siteKey}
  onChange={handleRecaptchaChange}
/>
```

## Security Considerations

1. **Encryption**: Secret keys are encrypted using Fernet (symmetric encryption) before storage
2. **Secure Generation**: Keys are generated via Google's reCAPTCHA Admin API
3. **Domain Restriction**: Each key is restricted to a single domain
4. **Automatic Cleanup**: Keys are deleted when custom domain is removed

## Troubleshooting

### "RECAPTCHA_ADMIN_API_KEY not configured"

- Ensure `RECAPTCHA_ADMIN_API_KEY` is set in your `.env` file
- Verify the API key has access to reCAPTCHA Enterprise API

### "Failed to decrypt domain reCAPTCHA secret"

- Check that `RECAPTCHA_ENCRYPTION_KEY` is set correctly
- Ensure it's the same key used during encryption
- Key must be 32 url-safe base64-encoded bytes

### "Domain key not provisioned"

- Check logs for provisioning errors during domain verification
- Manually trigger provisioning: re-verify the custom domain
- Verify your Google Cloud project has reCAPTCHA Enterprise API enabled

### Keys not appearing in form response

- Ensure database migration was run successfully
- Check that `recaptcha_site_key` column exists in `forms` table
- Verify form has been re-verified after migration

## Testing

### Test Domain Verification with reCAPTCHA Provisioning

```bash
curl -X POST https://api.cleanenroll.com/forms/YOUR_FORM_ID/custom-domain/verify \
  -H "Content-Type: application/json" \
  -d '{"customDomain": "forms.example.com"}'
```

Expected response includes `"recaptchaProvisioned": true`

### Verify Keys in Database

```sql
SELECT 
  id, 
  custom_domain, 
  recaptcha_site_key,
  recaptcha_key_created_at
FROM forms
WHERE custom_domain IS NOT NULL;
```

## Fallback Behavior

If domain-specific keys are not available:
- System falls back to global `RECAPTCHA_SECRET_KEY` for verification
- Forms on main domain (cleanenroll.com) use global keys
- Non-custom-domain forms use global keys

## Migration Path

For existing custom domains:
1. Keys will be provisioned automatically on next domain re-verification
2. Or manually trigger: `POST /forms/{id}/custom-domain/verify` with existing domain
3. System continues working with global keys until domain-specific keys are provisioned

## Cost Considerations

- Google reCAPTCHA Enterprise has usage-based pricing
- Each custom domain requires a separate site key
- Monitor usage in Google Cloud Console
- Consider rate limiting domain verifications to prevent abuse

## References

- [Google reCAPTCHA Admin API](https://cloud.google.com/recaptcha-enterprise/docs/reference/rest)
- [reCAPTCHA Settings](https://developers.google.com/recaptcha/docs/settings)
- [Fernet Encryption](https://cryptography.io/en/latest/fernet/)
