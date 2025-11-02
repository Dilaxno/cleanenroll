"""
Affiliate stats and analytics endpoints
Tracks clicks, conversions, earnings, and analytics data
"""

from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy import text
from typing import Optional
import jwt
from datetime import datetime, timedelta
import os

router = APIRouter()

JWT_SECRET = os.getenv('JWT_SECRET', 'your-secret-key-change-in-production')
JWT_ALGORITHM = 'HS256'

async def get_db_connection():
    """Get database connection from pool"""
    from db.database import get_session
    session = get_session()
    return await session.__anext__()

async def verify_affiliate_token(token: str):
    """Verify JWT token and return affiliate_id"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get('type') != 'access':
            raise HTTPException(status_code=401, detail='Invalid token type')
        return payload['affiliate_id']
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail='Token expired')
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail='Invalid token')

@router.get('/stats')
async def get_affiliate_stats(token: str):
    """Get affiliate statistics"""
    session = None
    try:
        affiliate_id = await verify_affiliate_token(token)
        session = await get_db_connection()
        
        # Get total clicks
        clicks_result = await session.execute(
            text('SELECT COUNT(*) as count FROM affiliate_clicks WHERE affiliate_id = :affiliate_id'),
            {'affiliate_id': affiliate_id}
        )
        total_clicks = clicks_result.scalar() or 0
        
        # Get total signups (users who signed up with this affiliate code)
        signups_result = await session.execute(
            text('''
                SELECT COUNT(DISTINCT user_id) as count 
                FROM users 
                WHERE referral_code = (
                    SELECT affiliate_code FROM affiliates WHERE id = :affiliate_id
                )
            '''),
            {'affiliate_id': affiliate_id}
        )
        total_signups = signups_result.scalar() or 0
        
        # Get conversions and earnings
        conversions_result = await session.execute(
            text('''
                SELECT 
                    COUNT(*) as total_conversions,
                    COALESCE(SUM(commission_amount), 0) as total_earnings,
                    COALESCE(SUM(CASE WHEN status = 'pending' THEN commission_amount ELSE 0 END), 0) as pending_earnings
                FROM affiliate_conversions 
                WHERE affiliate_id = :affiliate_id
            '''),
            {'affiliate_id': affiliate_id}
        )
        conversions = conversions_result.mappings().first()
        
        # Get total paid out
        payouts_result = await session.execute(
            text('''
                SELECT COALESCE(SUM(amount), 0) as total_paid_out
                FROM affiliate_payouts
                WHERE affiliate_id = :affiliate_id AND status = 'paid'
            '''),
            {'affiliate_id': affiliate_id}
        )
        total_paid_out = payouts_result.scalar() or 0
        
        # Calculate conversion rate
        conversion_rate = (conversions['total_conversions'] / total_signups * 100) if total_signups > 0 else 0
        
        return {
            'totalEarnings': float(conversions['total_earnings']),
            'pendingEarnings': float(conversions['pending_earnings']),
            'totalPaidOut': float(total_paid_out),
            'totalSales': int(conversions['total_conversions']),
            'totalClicks': int(total_clicks),
            'totalSignups': int(total_signups),
            'totalConversions': int(conversions['total_conversions']),
            'conversionRate': round(conversion_rate, 1)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f'Error fetching affiliate stats: {str(e)}')
        raise HTTPException(status_code=500, detail='Error fetching stats')
    finally:
        if session:
            await session.close()

@router.get('/analytics/clicks')
async def get_clicks_analytics(token: str, days: int = 30):
    """Get clicks and signups over time"""
    session = None
    try:
        affiliate_id = await verify_affiliate_token(token)
        session = await get_db_connection()
        
        # Get affiliate code
        code_result = await session.execute(
            text('SELECT affiliate_code FROM affiliates WHERE id = :affiliate_id'),
            {'affiliate_id': affiliate_id}
        )
        affiliate_code = code_result.scalar()
        
        # Get clicks grouped by date
        clicks_result = await session.execute(
            text('''
                SELECT 
                    DATE(clicked_at) as date,
                    COUNT(*) as clicks
                FROM affiliate_clicks
                WHERE affiliate_id = :affiliate_id 
                AND clicked_at >= NOW() - INTERVAL ':days days'
                GROUP BY DATE(clicked_at)
                ORDER BY date ASC
            '''),
            {'affiliate_id': affiliate_id, 'days': days}
        )
        clicks_data = clicks_result.mappings().all()
        
        # Get signups grouped by date
        signups_result = await session.execute(
            text('''
                SELECT 
                    DATE(created_at) as date,
                    COUNT(*) as signups
                FROM users
                WHERE referral_code = :code
                AND created_at >= NOW() - INTERVAL ':days days'
                GROUP BY DATE(created_at)
                ORDER BY date ASC
            '''),
            {'code': affiliate_code, 'days': days}
        )
        signups_data = {row['date']: row['signups'] for row in signups_result.mappings().all()}
        
        # Combine data
        result = []
        for row in clicks_data:
            result.append({
                'date': row['date'].strftime('%b %d'),
                'clicks': int(row['clicks']),
                'signups': int(signups_data.get(row['date'], 0))
            })
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        print(f'Error fetching clicks analytics: {str(e)}')
        raise HTTPException(status_code=500, detail='Error fetching analytics')
    finally:
        if session:
            await session.close()

@router.get('/analytics/conversions')
async def get_conversions_analytics(token: str, days: int = 30):
    """Get conversions and revenue over time"""
    session = None
    try:
        affiliate_id = await verify_affiliate_token(token)
        session = await get_db_connection()
        
        # Get conversions and revenue grouped by date
        result = await session.execute(
            text('''
                SELECT 
                    DATE(converted_at) as date,
                    COUNT(*) as conversions,
                    COALESCE(SUM(commission_amount), 0) as revenue
                FROM affiliate_conversions
                WHERE affiliate_id = :affiliate_id 
                AND converted_at >= NOW() - INTERVAL ':days days'
                GROUP BY DATE(converted_at)
                ORDER BY date ASC
            '''),
            {'affiliate_id': affiliate_id, 'days': days}
        )
        
        data = []
        for row in result.mappings().all():
            data.append({
                'date': row['date'].strftime('%b %d'),
                'conversions': int(row['conversions']),
                'revenue': float(row['revenue'])
            })
        
        return data
        
    except HTTPException:
        raise
    except Exception as e:
        print(f'Error fetching conversions analytics: {str(e)}')
        raise HTTPException(status_code=500, detail='Error fetching analytics')
    finally:
        if session:
            await session.close()

@router.get('/analytics/countries')
async def get_countries_analytics(token: str):
    """Get sales distribution by country"""
    session = None
    try:
        affiliate_id = await verify_affiliate_token(token)
        session = await get_db_connection()
        
        # Get affiliate code
        code_result = await session.execute(
            text('SELECT affiliate_code FROM affiliates WHERE id = :affiliate_id'),
            {'affiliate_id': affiliate_id}
        )
        affiliate_code = code_result.scalar()
        
        # Get conversions grouped by country
        # Assuming affiliate_conversions table has country_code column
        result = await session.execute(
            text('''
                SELECT 
                    country_code as code,
                    COUNT(*) as count
                FROM affiliate_conversions
                WHERE affiliate_id = :affiliate_id
                AND country_code IS NOT NULL
                GROUP BY country_code
                ORDER BY count DESC
            '''),
            {'affiliate_id': affiliate_id}
        )
        
        data = []
        for row in result.mappings().all():
            data.append({
                'code': row['code'],
                'count': int(row['count'])
            })
        
        return data
        
    except HTTPException:
        raise
    except Exception as e:
        print(f'Error fetching countries analytics: {str(e)}')
        # Return empty array on error instead of failing
        return []
    finally:
        if session:
            await session.close()

@router.post('/track-click')
async def track_click(affiliate_code: str, ip_address: Optional[str] = None, 
                     user_agent: Optional[str] = None, referrer: Optional[str] = None):
    """Track affiliate click"""
    session = None
    try:
        session = await get_db_connection()
        
        # Get affiliate_id from code
        result = await session.execute(
            text('SELECT id FROM affiliates WHERE affiliate_code = :code AND is_active = true'),
            {'code': affiliate_code}
        )
        affiliate = result.fetchone()
        
        if not affiliate:
            raise HTTPException(status_code=404, detail='Affiliate not found')
        
        # Insert click record
        import secrets
        click_id = secrets.token_urlsafe(16)
        
        await session.execute(
            text('''
                INSERT INTO affiliate_clicks 
                (id, affiliate_id, affiliate_code, ip_address, user_agent, referrer, clicked_at)
                VALUES (:id, :affiliate_id, :code, :ip, :user_agent, :referrer, NOW())
            '''),
            {
                'id': click_id,
                'affiliate_id': affiliate['id'],
                'code': affiliate_code,
                'ip': ip_address,
                'user_agent': user_agent,
                'referrer': referrer
            }
        )
        
        # Update total clicks counter
        await session.execute(
            text('UPDATE affiliates SET total_clicks = total_clicks + 1 WHERE id = :affiliate_id'),
            {'affiliate_id': affiliate['id']}
        )
        
        await session.commit()
        
        return {'success': True, 'click_id': click_id}
        
    except HTTPException:
        if session:
            await session.rollback()
        raise
    except Exception as e:
        if session:
            await session.rollback()
        print(f'Error tracking click: {str(e)}')
        raise HTTPException(status_code=500, detail='Error tracking click')
    finally:
        if session:
            await session.close()
