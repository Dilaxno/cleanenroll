from fastapi import APIRouter, HTTPException, Request
from typing import Dict, Optional
from sqlalchemy import text
import dns.resolver
from db.database import async_session_maker  # type: ignore
from fastapi.responses import PlainTextResponse

router = APIRouter()

CUSTOM_DOMAIN_TARGET = "api.cleanenroll.com"  # Your backend host


def _normalize_domain(dom: Optional[str]) -> Optional[str]:
    """Normalize domain by trimming whitespace, lowercasing, and removing trailing dots."""
    if not dom:
        return None
    return dom.strip().lower().rstrip(".")


# ─────────────────────────────
# VERIFY CUSTOM DOMAIN (subdomain or apex)
# ─────────────────────────────
@router.post("/forms/{form_id}/custom-domain/verify")
async def verify_custom_domain(form_id: str, payload: Dict = None, domain: Optional[str] = None):
    """
    Verify that the user's custom domain (or subdomain) points to api.cleanenroll.com,
    and mark it ready for Caddy on-demand TLS and direct serving.
    """
    inbound_domain = _normalize_domain(
        domain or (payload or {}).get("customDomain") or (payload or {}).get("domain")
    )
    if not inbound_domain:
        raise HTTPException(status_code=400, detail="Missing custom domain")

    # Prevent duplicate usage across forms
    async with async_session_maker() as session:
        res = await session.execute(
            text("""
                SELECT id FROM forms
                WHERE LOWER(TRIM(BOTH '.' FROM COALESCE(custom_domain, ''))) = :dom
                  AND id <> :fid
                LIMIT 1
            """),
            {"dom": inbound_domain, "fid": form_id},
        )
        if res.first() is not None:
            raise HTTPException(status_code=409, detail="This domain is already used by another form")

    # DNS verification
    cname_ok, apex_ok = False, False
    try:
        answers = dns.resolver.resolve(inbound_domain + ".", "CNAME")
        targets = [str(rdata.target).rstrip('.').lower() for rdata in answers]
        cname_ok = any(t == CUSTOM_DOMAIN_TARGET for t in targets)
    except Exception:
        cname_ok = False

    if not cname_ok:
        # Compare IPs for apex domains (A/AAAA)
        try:
            def ips(host):
                found = set()
                for rr in ("A", "AAAA"):
                    try:
                        ans = dns.resolver.resolve(host + ".", rr)
                        for r in ans:
                            found.add(str(r))
                    except Exception:
                        pass
                return found
            apex_ok = bool(ips(inbound_domain) & ips(CUSTOM_DOMAIN_TARGET))
        except Exception:
            apex_ok = False

    if not (cname_ok or apex_ok):
        raise HTTPException(status_code=400, detail=f"Domain {inbound_domain} must point to {CUSTOM_DOMAIN_TARGET}")

    # Update verification status in Neon
    async with async_session_maker() as session:
        await session.execute(
            text("""
                UPDATE forms
                SET custom_domain = :dom,
                    custom_domain_verified = TRUE,
                    ssl_verified = TRUE,
                    updated_at = NOW()
                WHERE id = :fid
            """),
            {"fid": form_id, "dom": inbound_domain},
        )
        await session.commit()

    return {
        "verified": True,
        "domain": inbound_domain,
        "sslVerified": True,
        "mode": "caddy",
        "message": f"Domain {inbound_domain} verified and ready to serve directly via api.cleanenroll.com."
    }


# ─────────────────────────────
# ISSUE CERT (Caddy handles automatically)
# ─────────────────────────────
@router.post("/forms/{form_id}/custom-domain/issue-cert")
async def issue_cert(form_id: str):
    """Dummy endpoint (Caddy issues cert automatically on first HTTPS request)."""
    async with async_session_maker() as session:
        res = await session.execute(
            text("SELECT custom_domain, custom_domain_verified FROM forms WHERE id = :fid LIMIT 1"),
            {"fid": form_id},
        )
        row = res.mappings().first()

    if not row:
        raise HTTPException(status_code=404, detail="Form not found")

    domain_val = _normalize_domain(row.get("custom_domain"))
    if not domain_val:
        raise HTTPException(status_code=400, detail="No custom domain configured")
    if not bool(row.get("custom_domain_verified")):
        raise HTTPException(status_code=400, detail="Domain not verified yet")

    # Mirror Caddy's SSL-ready state
    async with async_session_maker() as session:
        await session.execute(
            text("""
                UPDATE forms SET ssl_verified = TRUE, updated_at = NOW()
                WHERE id = :fid
            """),
            {"fid": form_id},
        )
        await session.commit()

    return {
        "success": True,
        "domain": domain_val,
        "sslVerified": True,
        "mode": "caddy",
        "message": "SSL will be provisioned automatically by Caddy when the domain is accessed."
    }


# ─────────────────────────────
# CERT STATUS
# ─────────────────────────────
@router.get("/forms/{form_id}/custom-domain/cert-status")
async def get_cert_status(form_id: str):
    """Return verification and SSL readiness for the form's custom domain."""
    async with async_session_maker() as session:
        res = await session.execute(
            text("""
                SELECT custom_domain, custom_domain_verified, ssl_verified
                FROM forms WHERE id = :fid LIMIT 1
            """),
            {"fid": form_id},
        )
        row = res.mappings().first()

    if not row:
        raise HTTPException(status_code=404, detail="Form not found")

    return {
        "domain": row.get("custom_domain"),
        "verified": bool(row.get("custom_domain_verified")),
        "sslVerified": bool(row.get("ssl_verified")),
        "mode": "caddy",
        "message": "SSL automatically managed by Caddy via api.cleanenroll.com."
    }


# ─────────────────────────────
# RESOLVE DOMAIN → FORM
# ─────────────────────────────
@router.get("/resolve-domain/{hostname}")
async def resolve_domain(hostname: str):
    """Used by Caddy or frontend to find which form should be served for a given custom domain."""
    inbound_domain = _normalize_domain(hostname)
    async with async_session_maker() as session:
        res = await session.execute(
            text("""
                SELECT id, custom_domain
                FROM forms
                WHERE LOWER(TRIM(BOTH '.' FROM COALESCE(custom_domain, ''))) = :dom
                LIMIT 1
            """),
            {"dom": inbound_domain},
        )
        row = res.mappings().first()

    if not row:
        raise HTTPException(status_code=404, detail="No form bound to this domain")

    return {
        "formId": row.get("id"),
        "domain": row.get("custom_domain"),
        "message": "Form mapped successfully for custom domain."
    }


# ─────────────────────────────
# DELETE CUSTOM DOMAIN
# ─────────────────────────────
@router.delete("/forms/{form_id}/custom-domain")
async def delete_custom_domain(form_id: str):
    """Remove custom domain from the form in Neon DB."""
    async with async_session_maker() as session:
        await session.execute(
            text("""
                UPDATE forms
                SET custom_domain = NULL,
                    custom_domain_verified = FALSE,
                    ssl_verified = FALSE,
                    updated_at = NOW()
                WHERE id = :fid
            """),
            {"fid": form_id}
        )
        await session.commit()
    return {"success": True, "message": "Custom domain removed successfully"}


@router.api_route("/allow-domain", methods=["GET", "HEAD"])
async def allow_domain(request: Request):
    """
    Endpoint called by Caddy's on_demand_tls 'ask' directive.
    Returns 'yes' if the Host (or ?domain= param) is found in the DB.
    """
    domain = request.headers.get("Host") or request.query_params.get("domain")
    if not domain:
        return PlainTextResponse("no", status_code=403)

    domain = domain.strip().lower().rstrip(".")

    async with async_session_maker() as session:
        res = await session.execute(
            text("""
                SELECT id FROM forms
                WHERE LOWER(TRIM(BOTH '.' FROM COALESCE(custom_domain, ''))) = :dom
                LIMIT 1
            """),
            {"dom": domain}
        )
        row = res.first()

    if row:
        return PlainTextResponse("yes", status_code=200)
    return PlainTextResponse("no", status_code=403)
