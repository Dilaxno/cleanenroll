"""
OAuth 2.0 Service for CleanEnroll
Handles token generation, validation, and management
"""
import secrets
import hashlib
import base64
import hmac
import json
import time
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Any
from db.database import async_session_maker
from sqlalchemy import text
import httpx
import logging

logger = logging.getLogger(__name__)

# Token configuration
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # 1 hour
REFRESH_TOKEN_EXPIRE_DAYS = 30
AUTHORIZATION_CODE_EXPIRE_MINUTES = 10


class OAuthService:
    """Service for OAuth 2.0 operations"""

    @staticmethod
    def generate_client_credentials() -> Tuple[str, str, str]:
        """Generate client_id, client_secret, and secret_hash"""
        client_id = f"ce_{secrets.token_urlsafe(24)}"
        client_secret = f"ces_{secrets.token_urlsafe(32)}"
        secret_hash = hashlib.sha256(client_secret.encode()).hexdigest()
        return client_id, client_secret, secret_hash

    @staticmethod
    def generate_authorization_code() -> str:
        """Generate a secure authorization code"""
        return secrets.token_urlsafe(48)

    @staticmethod
    def generate_access_token() -> Tuple[str, str]:
        """Generate access token and its hash"""
        token = f"ceat_{secrets.token_urlsafe(40)}"
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        return token, token_hash

    @staticmethod
    def generate_refresh_token() -> Tuple[str, str]:
        """Generate refresh token and its hash"""
        token = f"cert_{secrets.token_urlsafe(48)}"
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        return token, token_hash

    @staticmethod
    def generate_webhook_secret() -> str:
        """Generate webhook signing secret"""
        return secrets.token_urlsafe(32)

    @staticmethod
    def hash_token(token: str) -> str:
        """Hash a token for storage/comparison"""
        return hashlib.sha256(token.encode()).hexdigest()

    @staticmethod
    def verify_pkce(code_verifier: str, code_challenge: str, method: str = "S256") -> bool:
        """Verify PKCE code challenge"""
        if method == "plain":
            return code_verifier == code_challenge
        elif method == "S256":
            computed = base64.urlsafe_b64encode(
                hashlib.sha256(code_verifier.encode()).digest()
            ).rstrip(b"=").decode()
            return computed == code_challenge
        return False

    @staticmethod
    def sign_webhook_payload(payload: dict, secret: str) -> str:
        """Sign webhook payload using HMAC-SHA256"""
        payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        timestamp = str(int(time.time()))
        signed_payload = f"{timestamp}.{payload_bytes.decode()}"
        signature = hmac.new(
            secret.encode(),
            signed_payload.encode(),
            hashlib.sha256
        ).hexdigest()
        return f"t={timestamp},v1={signature}"

    @staticmethod
    def verify_webhook_signature(payload: str, signature: str, secret: str, tolerance: int = 300) -> bool:
        """Verify webhook signature with timestamp tolerance"""
        try:
            parts = dict(p.split("=") for p in signature.split(","))
            timestamp = int(parts.get("t", 0))
            expected_sig = parts.get("v1", "")

            # Check timestamp tolerance
            if abs(time.time() - timestamp) > tolerance:
                return False

            signed_payload = f"{timestamp}.{payload}"
            computed_sig = hmac.new(
                secret.encode(),
                signed_payload.encode(),
                hashlib.sha256
            ).hexdigest()
            return hmac.compare_digest(computed_sig, expected_sig)
        except Exception:
            return False

    async def get_client(self, client_id: str) -> Optional[Dict[str, Any]]:
        """Get OAuth client by client_id"""
        async with async_session_maker() as session:
            result = await session.execute(
                text("""SELECT id, client_id, client_secret_hash, name, description,
                              user_id, redirect_uris, allowed_scopes, grant_types,
                              is_confidential, is_active, logo_url, website_url,
                              webhook_url, webhook_secret, created_at, updated_at
                       FROM oauth_clients WHERE client_id = :client_id"""),
                {"client_id": client_id}
            )
            row = result.fetchone()
            if not row:
                return None
            return {
                "id": str(row[0]),
                "client_id": row[1],
                "client_secret_hash": row[2],
                "name": row[3],
                "description": row[4],
                "user_id": row[5],
                "redirect_uris": row[6],
                "allowed_scopes": row[7],
                "grant_types": row[8],
                "is_confidential": row[9],
                "is_active": row[10],
                "logo_url": row[11],
                "website_url": row[12],
                "webhook_url": row[13],
                "webhook_secret": row[14],
                "created_at": row[15],
                "updated_at": row[16],
            }

    async def verify_client_secret(self, client_id: str, client_secret: str) -> bool:
        """Verify client credentials"""
        client = await self.get_client(client_id)
        if not client or not client["is_active"]:
            return False
        secret_hash = self.hash_token(client_secret)
        return hmac.compare_digest(secret_hash, client["client_secret_hash"])

    async def validate_redirect_uri(self, client_id: str, redirect_uri: str) -> bool:
        """Validate redirect URI against registered URIs"""
        client = await self.get_client(client_id)
        if not client:
            return False
        return redirect_uri in client["redirect_uris"]

    async def validate_scopes(self, client_id: str, requested_scopes: str) -> Tuple[bool, list]:
        """Validate requested scopes against allowed scopes"""
        client = await self.get_client(client_id)
        if not client:
            return False, []
        requested = set(requested_scopes.split())
        allowed = set(client["allowed_scopes"])
        valid_scopes = list(requested & allowed)
        return len(valid_scopes) == len(requested), valid_scopes

    async def create_authorization_code(
        self,
        client_id: str,
        user_id: str,
        redirect_uri: str,
        scope: str,
        code_challenge: Optional[str] = None,
        code_challenge_method: Optional[str] = None
    ) -> str:
        """Create and store authorization code"""
        code = self.generate_authorization_code()
        expires_at = datetime.utcnow() + timedelta(minutes=AUTHORIZATION_CODE_EXPIRE_MINUTES)

        async with async_session_maker() as session:
            await session.execute(
                text("""INSERT INTO oauth_authorization_codes
                       (code, client_id, user_id, redirect_uri, scope,
                        code_challenge, code_challenge_method, expires_at)
                       VALUES (:code, :client_id, :user_id, :redirect_uri, :scope,
                               :code_challenge, :code_challenge_method, :expires_at)"""),
                {
                    "code": code,
                    "client_id": client_id,
                    "user_id": user_id,
                    "redirect_uri": redirect_uri,
                    "scope": scope,
                    "code_challenge": code_challenge,
                    "code_challenge_method": code_challenge_method,
                    "expires_at": expires_at,
                }
            )
            await session.commit()
        return code

    async def exchange_authorization_code(
        self,
        code: str,
        client_id: str,
        redirect_uri: str,
        code_verifier: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Exchange authorization code for tokens"""
        async with async_session_maker() as session:
            # Get and validate authorization code
            result = await session.execute(
                text("""SELECT id, client_id, user_id, redirect_uri, scope,
                              code_challenge, code_challenge_method, expires_at, used_at
                       FROM oauth_authorization_codes
                       WHERE code = :code AND client_id = :client_id"""),
                {"code": code, "client_id": client_id}
            )
            row = result.fetchone()

            if not row:
                return None

            code_id, stored_client_id, user_id, stored_redirect_uri, scope, \
                code_challenge, code_challenge_method, expires_at, used_at = row

            # Validate code hasn't been used
            if used_at:
                # Code reuse detected - revoke all tokens for this code
                logger.warning(f"Authorization code reuse detected for client {client_id}")
                return None

            # Validate expiration
            if datetime.utcnow() > expires_at:
                return None

            # Validate redirect_uri
            if redirect_uri != stored_redirect_uri:
                return None

            # Validate PKCE if code_challenge was provided
            if code_challenge:
                if not code_verifier:
                    return None
                if not self.verify_pkce(code_verifier, code_challenge, code_challenge_method or "S256"):
                    return None

            # Mark code as used
            await session.execute(
                text("UPDATE oauth_authorization_codes SET used_at = NOW() WHERE id = :id"),
                {"id": code_id}
            )

            # Generate tokens
            access_token, access_token_hash = self.generate_access_token()
            refresh_token, refresh_token_hash = self.generate_refresh_token()

            access_expires = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            refresh_expires = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

            # Store access token
            result = await session.execute(
                text("""INSERT INTO oauth_access_tokens
                       (token_hash, client_id, user_id, scope, expires_at)
                       VALUES (:token_hash, :client_id, :user_id, :scope, :expires_at)
                       RETURNING id"""),
                {
                    "token_hash": access_token_hash,
                    "client_id": client_id,
                    "user_id": user_id,
                    "scope": scope,
                    "expires_at": access_expires,
                }
            )
            access_token_id = result.fetchone()[0]

            # Store refresh token
            await session.execute(
                text("""INSERT INTO oauth_refresh_tokens
                       (token_hash, access_token_id, client_id, user_id, scope, expires_at)
                       VALUES (:token_hash, :access_token_id, :client_id, :user_id, :scope, :expires_at)"""),
                {
                    "token_hash": refresh_token_hash,
                    "access_token_id": access_token_id,
                    "client_id": client_id,
                    "user_id": user_id,
                    "scope": scope,
                    "expires_at": refresh_expires,
                }
            )

            await session.commit()

            return {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                "refresh_token": refresh_token,
                "scope": scope,
            }

    async def refresh_access_token(
        self,
        refresh_token: str,
        client_id: str
    ) -> Optional[Dict[str, Any]]:
        """Refresh access token using refresh token"""
        token_hash = self.hash_token(refresh_token)

        async with async_session_maker() as session:
            # Validate refresh token
            result = await session.execute(
                text("""SELECT id, client_id, user_id, scope, expires_at, revoked_at
                       FROM oauth_refresh_tokens
                       WHERE token_hash = :token_hash AND client_id = :client_id"""),
                {"token_hash": token_hash, "client_id": client_id}
            )
            row = result.fetchone()

            if not row:
                return None

            token_id, stored_client_id, user_id, scope, expires_at, revoked_at = row

            if revoked_at or datetime.utcnow() > expires_at:
                return None

            # Generate new access token
            new_access_token, new_access_token_hash = self.generate_access_token()
            access_expires = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

            # Store new access token
            result = await session.execute(
                text("""INSERT INTO oauth_access_tokens
                       (token_hash, client_id, user_id, scope, expires_at)
                       VALUES (:token_hash, :client_id, :user_id, :scope, :expires_at)
                       RETURNING id"""),
                {
                    "token_hash": new_access_token_hash,
                    "client_id": client_id,
                    "user_id": user_id,
                    "scope": scope,
                    "expires_at": access_expires,
                }
            )
            new_access_token_id = result.fetchone()[0]

            # Update refresh token to point to new access token
            await session.execute(
                text("UPDATE oauth_refresh_tokens SET access_token_id = :access_token_id WHERE id = :id"),
                {"access_token_id": new_access_token_id, "id": token_id}
            )

            await session.commit()

            return {
                "access_token": new_access_token,
                "token_type": "Bearer",
                "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                "scope": scope,
            }

    async def validate_access_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate access token and return token data"""
        token_hash = self.hash_token(token)

        async with async_session_maker() as session:
            result = await session.execute(
                text("""SELECT id, client_id, user_id, scope, expires_at, revoked_at
                       FROM oauth_access_tokens
                       WHERE token_hash = :token_hash"""),
                {"token_hash": token_hash}
            )
            row = result.fetchone()

            if not row:
                return None

            token_id, client_id, user_id, scope, expires_at, revoked_at = row

            if revoked_at or datetime.utcnow() > expires_at:
                return None

            return {
                "token_id": str(token_id),
                "client_id": client_id,
                "user_id": user_id,
                "scope": scope,
                "expires_at": expires_at,
            }

    async def revoke_token(self, token: str, token_type_hint: Optional[str] = None) -> bool:
        """Revoke access or refresh token"""
        token_hash = self.hash_token(token)

        async with async_session_maker() as session:
            # Try access token first (or if hinted)
            if token_type_hint != "refresh_token":
                result = await session.execute(
                    text("""UPDATE oauth_access_tokens
                           SET revoked_at = NOW()
                           WHERE token_hash = :token_hash AND revoked_at IS NULL
                           RETURNING id"""),
                    {"token_hash": token_hash}
                )
                if result.fetchone():
                    await session.commit()
                    return True

            # Try refresh token
            if token_type_hint != "access_token":
                result = await session.execute(
                    text("""UPDATE oauth_refresh_tokens
                           SET revoked_at = NOW()
                           WHERE token_hash = :token_hash AND revoked_at IS NULL
                           RETURNING id, access_token_id"""),
                    {"token_hash": token_hash}
                )
                row = result.fetchone()
                if row:
                    # Also revoke associated access token
                    if row[1]:
                        await session.execute(
                            text("UPDATE oauth_access_tokens SET revoked_at = NOW() WHERE id = :id"),
                            {"id": row[1]}
                        )
                    await session.commit()
                    return True

            return False

    async def check_user_consent(self, user_id: str, client_id: str, scope: str) -> bool:
        """Check if user has already consented to the requested scopes"""
        async with async_session_maker() as session:
            result = await session.execute(
                text("""SELECT scope FROM oauth_consents
                       WHERE user_id = :user_id AND client_id = :client_id
                       AND revoked_at IS NULL"""),
                {"user_id": user_id, "client_id": client_id}
            )
            row = result.fetchone()
            if not row:
                return False

            consented_scopes = set(row[0].split())
            requested_scopes = set(scope.split())
            return requested_scopes.issubset(consented_scopes)

    async def save_user_consent(self, user_id: str, client_id: str, scope: str) -> None:
        """Save user consent for client scopes"""
        async with async_session_maker() as session:
            await session.execute(
                text("""INSERT INTO oauth_consents (user_id, client_id, scope)
                       VALUES (:user_id, :client_id, :scope)
                       ON CONFLICT (user_id, client_id)
                       DO UPDATE SET scope = :scope, granted_at = NOW(), revoked_at = NULL"""),
                {"user_id": user_id, "client_id": client_id, "scope": scope}
            )
            await session.commit()


# Webhook delivery service
class WebhookService:
    """Service for webhook delivery"""

    def __init__(self, oauth_service: OAuthService):
        self.oauth_service = oauth_service

    async def queue_webhook_event(
        self,
        client_id: str,
        event_type: str,
        data: dict
    ) -> Optional[str]:
        """Queue a webhook event for delivery"""
        client = await self.oauth_service.get_client(client_id)
        if not client or not client["webhook_url"] or not client["webhook_secret"]:
            return None

        payload = {
            "id": secrets.token_urlsafe(16),
            "event": event_type,
            "created_at": datetime.utcnow().isoformat() + "Z",
            "data": data,
        }

        signature = self.oauth_service.sign_webhook_payload(payload, client["webhook_secret"])

        async with async_session_maker() as session:
            result = await session.execute(
                text("""INSERT INTO oauth_webhook_events
                       (client_id, event_type, payload, signature)
                       VALUES (:client_id, :event_type, :payload, :signature)
                       RETURNING id"""),
                {
                    "client_id": client_id,
                    "event_type": event_type,
                    "payload": json.dumps(payload),
                    "signature": signature,
                }
            )
            event_id = str(result.fetchone()[0])
            await session.commit()

        # Attempt immediate delivery
        await self.deliver_webhook(event_id)
        return event_id

    async def deliver_webhook(self, event_id: str) -> bool:
        """Attempt to deliver a webhook event"""
        async with async_session_maker() as session:
            result = await session.execute(
                text("""SELECT e.id, e.client_id, e.payload, e.signature, c.webhook_url
                       FROM oauth_webhook_events e
                       JOIN oauth_clients c ON e.client_id = c.client_id
                       WHERE e.id = :event_id AND e.status = 'pending'"""),
                {"event_id": event_id}
            )
            row = result.fetchone()
            if not row:
                return False

            _, client_id, payload, signature, webhook_url = row

            start_time = time.time()
            status_code = None
            response_body = None
            success = False

            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    response = await client.post(
                        webhook_url,
                        content=payload,
                        headers={
                            "Content-Type": "application/json",
                            "X-CleanEnroll-Signature": signature,
                            "X-CleanEnroll-Event": json.loads(payload)["event"],
                        }
                    )
                    status_code = response.status_code
                    response_body = response.text[:1000]
                    success = 200 <= status_code < 300
            except Exception as e:
                response_body = str(e)[:1000]

            response_time_ms = int((time.time() - start_time) * 1000)

            # Log delivery attempt
            await session.execute(
                text("""INSERT INTO oauth_webhook_deliveries
                       (event_id, client_id, webhook_url, status_code, response_body, response_time_ms)
                       VALUES (:event_id, :client_id, :webhook_url, :status_code, :response_body, :response_time_ms)"""),
                {
                    "event_id": event_id,
                    "client_id": client_id,
                    "webhook_url": webhook_url,
                    "status_code": status_code,
                    "response_body": response_body,
                    "response_time_ms": response_time_ms,
                }
            )

            # Update event status
            new_status = "delivered" if success else "failed"
            await session.execute(
                text("""UPDATE oauth_webhook_events
                       SET status = :status, attempts = attempts + 1,
                           last_attempt_at = NOW(),
                           delivered_at = CASE WHEN :success THEN NOW() ELSE NULL END,
                           error_message = CASE WHEN :success THEN NULL ELSE :error END
                       WHERE id = :event_id"""),
                {
                    "status": new_status,
                    "success": success,
                    "error": response_body if not success else None,
                    "event_id": event_id,
                }
            )
            await session.commit()

            return success


# Singleton instances
oauth_service = OAuthService()
webhook_service = WebhookService(oauth_service)
