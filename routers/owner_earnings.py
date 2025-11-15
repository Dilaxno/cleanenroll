import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request, Query

# DB session
try:
    from db.database import async_session_maker  # type: ignore
except Exception:
    from ..db.database import async_session_maker  # type: ignore

# Optional Firebase auth (owner gate)
try:
    import firebase_admin  # type: ignore
    from firebase_admin import auth as admin_auth  # type: ignore
    _FB_AVAILABLE = True
except Exception:
    firebase_admin = None  # type: ignore
    admin_auth = None  # type: ignore
    _FB_AVAILABLE = False

from sqlalchemy import text as _text

logger = logging.getLogger("backend.earnings")

router = APIRouter(prefix="/api/earnings", tags=["earnings"])


def _parse_iso(dt: Optional[str]) -> Optional[datetime]:
    if not dt:
        return None
    try:
        # Allow both "YYYY-MM-DD" and ISO8601
        if len(dt) == 10 and dt.count("-") == 2:
            return datetime.fromisoformat(dt)
        return datetime.fromisoformat(str(dt).replace("Z", "+00:00"))
    except Exception:
        return None


def _verify_uid_from_request(request: Request) -> Optional[str]:
    if not _FB_AVAILABLE:
        return None
    authz = request.headers.get("authorization") or request.headers.get("Authorization")
    if not authz or not authz.lower().startswith("bearer "):
        return None
    token = authz.split(" ", 1)[1].strip()
    if not token:
        return None
    try:
        decoded = admin_auth.verify_id_token(token)
        return decoded.get("uid")
    except Exception:
        return None


def _enforce_owner_access(or_uid: Optional[str], owner_id: Optional[str]) -> None:
    """
    Simple owner gate: if Firebase is configured and a uid is present,
    enforce uid == owner_id when owner_id is provided.
    """
    if or_uid and owner_id and str(or_uid) != str(owner_id):
        raise HTTPException(status_code=403, detail="Not allowed")


@router.get("/summary")
async def earnings_summary(
    request: Request,
    owner_id: str = Query(..., description="Owner UID"),
    start: Optional[str] = Query(None, description="Start ISO date (inclusive)"),
    end: Optional[str] = Query(None, description="End ISO date (inclusive)"),
) -> Dict[str, Any]:
    """
    Return totals and month buckets for succeeded transactions.
    - Totals: gross, fees, net
    - Monthly buckets (date_trunc month): gross, fees, net
    All amounts are in smallest currency unit.
    """
    uid = _verify_uid_from_request(request)
    _enforce_owner_access(uid, owner_id)

    dt_start = _parse_iso(start)
    dt_end = _parse_iso(end)

    where: List[str] = ["owner_id = :owner_id", "status = 'succeeded'"]
    params: Dict[str, Any] = {"owner_id": owner_id}
    if dt_start:
        where.append("created_at >= :start")
        params["start"] = dt_start
    if dt_end:
        where.append("created_at <= :end")
        params["end"] = dt_end

    where_sql = " AND ".join(where)
    try:
        async with async_session_maker() as session:
            # Totals
            res_tot = await session.execute(
                _text(
                    f"""
                    SELECT
                        COALESCE(SUM(total_amount),0) AS total_gross,
                        COALESCE(SUM(fee_amount),0)   AS total_fees,
                        COALESCE(SUM(net_amount),0)   AS total_net,
                        MAX(currency)                 AS currency
                    FROM owner_transactions
                    WHERE {where_sql}
                    """
                ),
                params,
            )
            trow = res_tot.mappings().first() or {}
            totals = {
                "gross": int(trow.get("total_gross") or 0),
                "fees": int(trow.get("total_fees") or 0),
                "net": int(trow.get("total_net") or 0),
                "currency": (trow.get("currency") or "USD"),
            }

            # Monthly buckets
            res_months = await session.execute(
                _text(
                    f"""
                    SELECT
                        date_trunc('month', created_at) AS period,
                        COALESCE(SUM(total_amount),0)   AS gross,
                        COALESCE(SUM(fee_amount),0)     AS fees,
                        COALESCE(SUM(net_amount),0)     AS net
                    FROM owner_transactions
                    WHERE {where_sql}
                    GROUP BY 1
                    ORDER BY 1 ASC
                    """
                ),
                params,
            )
            buckets: List[Dict[str, Any]] = []
            for r in res_months:
                buckets.append(
                    {
                        "period": r[0].isoformat() if r[0] else None,
                        "gross": int(r[1] or 0),
                        "fees": int(r[2] or 0),
                        "net": int(r[3] or 0),
                    }
                )

            return {"owner_id": owner_id, "totals": totals, "monthly": buckets}
    except HTTPException:
        raise
    except Exception:
        logger.exception("[earnings.summary] query failed")
        raise HTTPException(status_code=500, detail="Failed to load summary")


@router.get("/transactions")
async def list_transactions(
    request: Request,
    owner_id: str = Query(..., description="Owner UID"),
    start: Optional[str] = Query(None),
    end: Optional[str] = Query(None),
    page_number: int = Query(0, ge=0),
    page_size: int = Query(20, ge=1, le=100),
) -> Dict[str, Any]:
    """
    Paginated transactions for an owner, newest first.
    """
    uid = _verify_uid_from_request(request)
    _enforce_owner_access(uid, owner_id)

    dt_start = _parse_iso(start)
    dt_end = _parse_iso(end)

    where: List[str] = ["owner_id = :owner_id"]
    params: Dict[str, Any] = {"owner_id": owner_id}
    if dt_start:
        where.append("created_at >= :start")
        params["start"] = dt_start
    if dt_end:
        where.append("created_at <= :end")
        params["end"] = dt_end

    where_sql = " AND ".join(where)
    limit = int(page_size)
    offset = int(page_number) * limit

    try:
        async with async_session_maker() as session:
            # list
            res = await session.execute(
                _text(
                    f"""
                    SELECT
                        payment_id, form_id, submission_id, status,
                        total_amount, fee_amount, net_amount, currency,
                        customer_email, payment_method_type,
                        created_at
                    FROM owner_transactions
                    WHERE {where_sql}
                    ORDER BY created_at DESC
                    LIMIT :limit OFFSET :offset
                    """
                ),
                {**params, "limit": limit, "offset": offset},
            )
            items: List[Dict[str, Any]] = []
            for r in res:
                items.append(
                    {
                        "payment_id": r[0],
                        "form_id": r[1],
                        "submission_id": r[2],
                        "status": r[3],
                        "total_amount": int(r[4] or 0),
                        "fee_amount": int(r[5] or 0),
                        "net_amount": int(r[6] or 0),
                        "currency": r[7] or "USD",
                        "customer_email": r[8],
                        "payment_method_type": r[9],
                        "created_at": r[10].isoformat() if r[10] else None,
                    }
                )

            # count
            res_ct = await session.execute(
                _text(
                    f"""
                    SELECT COUNT(*) FROM owner_transactions
                    WHERE {where_sql}
                    """
                ),
                params,
            )
            total = int(res_ct.scalar() or 0)
            return {"items": items, "page_number": page_number, "page_size": page_size, "total": total}
    except HTTPException:
        raise
    except Exception:
        logger.exception("[earnings.transactions] query failed")
        raise HTTPException(status_code=500, detail="Failed to load transactions")


@router.get("/payouts")
async def list_payouts(
    request: Request,
    owner_id: str = Query(..., description="Owner UID"),
    page_number: int = Query(0, ge=0),
    page_size: int = Query(20, ge=1, le=100),
) -> Dict[str, Any]:
    """
    List internal payout batches for an owner.
    """
    uid = _verify_uid_from_request(request)
    _enforce_owner_access(uid, owner_id)

    limit = int(page_size)
    offset = int(page_number) * limit

    try:
        async with async_session_maker() as session:
            res = await session.execute(
                _text(
                    """
                    SELECT id, owner_id, period_start, period_end, total_gross, total_fees, total_net, status, notes, created_at, paid_at
                    FROM owner_payouts
                    WHERE owner_id = :owner_id
                    ORDER BY created_at DESC
                    LIMIT :limit OFFSET :offset
                    """
                ),
                {"owner_id": owner_id, "limit": limit, "offset": offset},
            )
            items: List[Dict[str, Any]] = []
            for r in res:
                items.append(
                    {
                        "id": r[0],
                        "owner_id": r[1],
                        "period_start": r[2].isoformat() if r[2] else None,
                        "period_end": r[3].isoformat() if r[3] else None,
                        "total_gross": int(r[4] or 0),
                        "total_fees": int(r[5] or 0),
                        "total_net": int(r[6] or 0),
                        "status": r[7],
                        "notes": r[8],
                        "created_at": r[9].isoformat() if r[9] else None,
                        "paid_at": r[10].isoformat() if r[10] else None,
                    }
                )

            res_ct = await session.execute(
                _text("SELECT COUNT(*) FROM owner_payouts WHERE owner_id = :owner_id"),
                {"owner_id": owner_id},
            )
            total = int(res_ct.scalar() or 0)
            return {"items": items, "page_number": page_number, "page_size": page_size, "total": total}
    except HTTPException:
        raise
    except Exception:
        logger.exception("[earnings.payouts] query failed")
        raise HTTPException(status_code=500, detail="Failed to load payouts")


@router.post("/payouts/create")
async def create_payout_batch(
    request: Request,
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Create a payout batch over a period for an owner by aggregating succeeded, unbatched transactions.
    Body:
    {
      "owner_id": "uid_123",
      "period_start": "2025-11-01T00:00:00Z",
      "period_end":   "2025-11-30T23:59:59Z",
      "notes": "Monthly payout"
    }
    """
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Invalid payload")

    owner_id = (payload.get("owner_id") or "").strip()
    if not owner_id:
        raise HTTPException(status_code=400, detail="owner_id is required")

    uid = _verify_uid_from_request(request)
    _enforce_owner_access(uid, owner_id)

    period_start = _parse_iso(payload.get("period_start"))
    period_end = _parse_iso(payload.get("period_end"))
    if not (period_start and period_end):
        raise HTTPException(status_code=400, detail="period_start and period_end are required ISO datetimes")

    notes = (payload.get("notes") or "").strip() or None

    try:
        async with async_session_maker() as session:
            # Aggregate totals for unbatched succeeded transactions in the window
            res = await session.execute(
                _text(
                    """
                    SELECT
                        COALESCE(SUM(total_amount),0) AS gross,
                        COALESCE(SUM(fee_amount),0)   AS fees,
                        COALESCE(SUM(net_amount),0)   AS net
                    FROM owner_transactions
                    WHERE owner_id = :owner_id
                      AND status = 'succeeded'
                      AND payout_id IS NULL
                      AND created_at >= :start
                      AND created_at <= :end
                    """
                ),
                {"owner_id": owner_id, "start": period_start, "end": period_end},
            )
            row = res.mappings().first() or {}
            gross = int(row.get("gross") or 0)
            fees = int(row.get("fees") or 0)
            net = int(row.get("net") or 0)

            if net <= 0:
                raise HTTPException(status_code=409, detail="No eligible transactions to batch for payout")

            # Create payout id
            import uuid
            payout_id = f"pyt_{uuid.uuid4().hex[:24]}"

            # Insert payout and link transactions in a tx
            await session.execute(
                _text(
                    """
                    INSERT INTO owner_payouts
                        (id, owner_id, period_start, period_end, total_gross, total_fees, total_net, status, notes, created_at)
                    VALUES
                        (:id, :owner_id, :start, :end, :gross, :fees, :net, 'pending', :notes, NOW())
                    """
                ),
                {
                    "id": payout_id,
                    "owner_id": owner_id,
                    "start": period_start,
                    "end": period_end,
                    "gross": gross,
                    "fees": fees,
                    "net": net,
                    "notes": notes,
                },
            )

            await session.execute(
                _text(
                    """
                    UPDATE owner_transactions
                    SET payout_id = :payout_id, updated_at = NOW()
                    WHERE owner_id = :owner_id
                      AND status = 'succeeded'
                      AND payout_id IS NULL
                      AND created_at >= :start
                      AND created_at <= :end
                    """
                ),
                {"payout_id": payout_id, "owner_id": owner_id, "start": period_start, "end": period_end},
            )

            await session.commit()

            return {
                "id": payout_id,
                "owner_id": owner_id,
                "period_start": period_start.isoformat(),
                "period_end": period_end.isoformat(),
                "total_gross": gross,
                "total_fees": fees,
                "total_net": net,
                "status": "pending",
                "notes": notes,
            }
    except HTTPException:
        raise
    except Exception:
        logger.exception("[earnings.payouts.create] failed")
        raise HTTPException(status_code=500, detail="Failed to create payout batch")