# Submission Data Encryption Setup

CleanEnroll now encrypts all form submission data using AES-256-GCM before storing in the database.

## Generate Encryption Key

Run this command to generate a secure 256-bit encryption key:

```bash
python -c "from utils.encryption import generate_encryption_key; print(generate_encryption_key())"
```

This will output a base64-encoded key like:
```
a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6==
```

## Add to Environment

Add the generated key to your `.env` file:

```bash
SUBMISSION_ENCRYPTION_KEY=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6==
```

**IMPORTANT**: 
- Keep this key SECRET and secure
- Never commit it to version control
- Store it in a secure secrets manager for production
- If you lose the key, encrypted submissions cannot be recovered

## How It Works

### Encryption (on submission)
1. User submits form data
2. Backend encrypts data using AES-256-GCM
3. Encrypted ciphertext stored in database
4. No plaintext submission data touches the database

### Decryption (on read)
1. Authorized user requests submissions
2. Backend retrieves encrypted data
3. Decrypts using the secret key
4. Returns plaintext to authorized user only

### Security Features
- **AES-256-GCM**: Industry-standard authenticated encryption
- **Random IVs**: Each submission uses a unique 96-bit initialization vector
- **Authentication tags**: Prevents tampering with encrypted data
- **Key isolation**: Key only in environment, never in code
- **Access control**: Only form owners can decrypt submissions

## Files Modified

- `backend/utils/encryption.py` - Encryption/decryption functions
- `backend/services/submissions_service.py` - Encrypt on create, decrypt on read
- `backend/routers/builder.py` - Decrypt when listing/retrieving submissions
- `backend/requirements.txt` - Already includes cryptography>=41.0.0

## Testing

After setting up the key:

1. Submit a test form
2. Check database - data field should be base64 encrypted string
3. Retrieve submission via API - should return decrypted plaintext
4. Verify unauthorized users cannot access submissions

## Production Deployment

For production:
- Use a secrets manager (AWS Secrets Manager, GCP Secret Manager, etc.)
- Rotate keys periodically (requires re-encrypting old data)
- Use separate keys for dev/staging/production
- Monitor for decryption failures in logs
- Have a key backup/recovery plan
