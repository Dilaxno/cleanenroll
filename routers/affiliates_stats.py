"""
Affiliate stats and analytics endpoints
Tracks clicks, conversions, earnings, and analytics data
"""

from fastapi import APIRouter, HTTPException, Depends, Request, Form
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
import jwt
from datetime import datetime, timedelta
import os
from db.database import get_session

router = APIRouter()

JWT_SECRET = os.getenv('JWT_SECRET', 'your-secret-key-change-in-production')
JWT_ALGORITHM = 'HS256'

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
async def get_affiliate_stats(token: str, session: AsyncSession = Depends(get_session)):
    """Get affiliate statistics"""
    try:
        affiliate_id = await verify_affiliate_token(token)
        
        # Get affiliate code first
        affiliate_result = await session.execute(
            text('SELECT affiliate_code FROM affiliates WHERE id = :affiliate_id'),
            {'affiliate_id': affiliate_id}
        )
        affiliate = affiliate_result.mappings().first()
        affiliate_code = affiliate['affiliate_code'] if affiliate else None
        
        # Get total clicks using affiliate_code for reliability
        clicks_result = await session.execute(
            text('SELECT COUNT(*) as count FROM affiliate_clicks WHERE affiliate_code = :code'),
            {'code': affiliate_code}
        )
        total_clicks = clicks_result.scalar() or 0
        
        # Get total signups (users who signed up with this affiliate code)
        # TODO: Implement referral_code column in users table
        total_signups = 0
        
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

@router.get('/analytics/clicks')
async def get_clicks_analytics(token: str, days: int = 30, session: AsyncSession = Depends(get_session)):
    """Get clicks and signups over time"""
    try:
        affiliate_id = await verify_affiliate_token(token)
        
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

@router.get('/analytics/conversions')
async def get_conversions_analytics(token: str, days: int = 30, session: AsyncSession = Depends(get_session)):
    """Get conversions and revenue over time"""
    try:
        affiliate_id = await verify_affiliate_token(token)
        
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

@router.get('/analytics/countries')
async def get_countries_analytics(token: str, session: AsyncSession = Depends(get_session)):
    """Get sales distribution by country"""
    try:
        affiliate_id = await verify_affiliate_token(token)
        
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

@router.get('/payouts')
async def get_payouts(token: str, session: AsyncSession = Depends(get_session)):
    """Get payout history for affiliate"""
    try:
        affiliate_id = await verify_affiliate_token(token)
        
        # Fetch all payouts for this affiliate
        result = await session.execute(
            text('''
                SELECT 
                    id,
                    amount,
                    status,
                    payment_method,
                    created_at,
                    paid_at
                FROM affiliate_payouts
                WHERE affiliate_id = :affiliate_id
                ORDER BY created_at DESC
            '''),
            {'affiliate_id': affiliate_id}
        )
        
        payouts = []
        for row in result.mappings().all():
            # Use paid_at if available, otherwise created_at
            payout_date = row['paid_at'] if row['paid_at'] else row['created_at']
            
            payouts.append({
                'id': row['id'],
                'amount': float(row['amount']),
                'status': row['status'],
                'method': row['payment_method'] or 'PayPal',
                'date': payout_date.strftime('%Y-%m-%d') if payout_date else 'N/A'
            })
        
        return payouts
        
    except HTTPException:
        raise
    except Exception as e:
        print(f'Error fetching payouts: {str(e)}')
        # Return empty array on error
        return []

@router.post('/track-click')
async def track_click(
    request: Request,
    affiliate_code: str = Form(...), 
    user_agent: Optional[str] = Form(None), 
    referrer: Optional[str] = Form(None),
    session: AsyncSession = Depends(get_session)
):
    """Track affiliate click with geolocation"""
    try:
        # Extract real client IP address
        client_ip = request.client.host if request.client else None
        # Check for forwarded IP (behind proxy/load balancer)
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            client_ip = forwarded_for.split(',')[0].strip()
        real_ip = request.headers.get('X-Real-IP') or client_ip
        
        # Get affiliate_id from code
        result = await session.execute(
            text('SELECT id FROM affiliates WHERE affiliate_code = :code AND is_active = true'),
            {'code': affiliate_code}
        )
        affiliate = result.mappings().first()
        
        if not affiliate:
            raise HTTPException(status_code=404, detail='Affiliate not found')
        
        # Get geolocation data
        country_code = None
        country = None
        city = None
        region = None
        latitude = None
        longitude = None
        
        try:
            from utils.geo import get_geo_info
            geo_info = get_geo_info(real_ip)
            if geo_info:
                country_code = geo_info.get('country_code')
                country = geo_info.get('country')
                city = geo_info.get('city')
                region = geo_info.get('region')
                latitude = geo_info.get('latitude')
                longitude = geo_info.get('longitude')
        except Exception as e:
            print(f'Error getting geo info: {str(e)}')
        
        # Parse device info from user agent
        device_type = 'desktop'
        browser = 'Unknown'
        os_name = 'Unknown'
        
        if user_agent:
            ua_lower = user_agent.lower()
            # Device type
            if 'mobile' in ua_lower or 'android' in ua_lower or 'iphone' in ua_lower:
                device_type = 'mobile'
            elif 'tablet' in ua_lower or 'ipad' in ua_lower:
                device_type = 'tablet'
            
            # Browser
            if 'edg' in ua_lower:
                browser = 'Edge'
            elif 'chrome' in ua_lower:
                browser = 'Chrome'
            elif 'safari' in ua_lower and 'chrome' not in ua_lower:
                browser = 'Safari'
            elif 'firefox' in ua_lower:
                browser = 'Firefox'
            elif 'opera' in ua_lower:
                browser = 'Opera'
            
            # OS
            if 'windows' in ua_lower:
                os_name = 'Windows'
            elif 'mac' in ua_lower:
                os_name = 'macOS'
            elif 'linux' in ua_lower:
                os_name = 'Linux'
            elif 'android' in ua_lower:
                os_name = 'Android'
            elif 'ios' in ua_lower or 'iphone' in ua_lower or 'ipad' in ua_lower:
                os_name = 'iOS'
        
        # Insert click record with geolocation
        import secrets
        click_id = secrets.token_urlsafe(16)
        
        await session.execute(
            text('''
                INSERT INTO affiliate_clicks 
                (id, affiliate_id, affiliate_code, ip_address, user_agent, referrer, 
                 country_code, country, city, region, latitude, longitude,
                 device_type, browser, os, clicked_at)
                VALUES (:id, :affiliate_id, :code, :ip, :user_agent, :referrer,
                        :country_code, :country, :city, :region, :latitude, :longitude,
                        :device_type, :browser, :os, NOW())
            '''),
            {
                'id': click_id,
                'affiliate_id': affiliate['id'],
                'code': affiliate_code,
                'ip': real_ip,
                'user_agent': user_agent,
                'referrer': referrer,
                'country_code': country_code,
                'country': country,
                'city': city,
                'region': region,
                'latitude': latitude,
                'longitude': longitude,
                'device_type': device_type,
                'browser': browser,
                'os': os_name
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
        await session.rollback()
        raise
    except Exception as e:
        await session.rollback()
        print(f'Error tracking click: {str(e)}')
        raise HTTPException(status_code=500, detail='Error tracking click')

@router.get('/live-tracking')
async def get_live_tracking(token: str, limit: int = 50, session: AsyncSession = Depends(get_session)):
    """Get recent affiliate activities with geolocation for live tracking"""
    try:
        affiliate_id = await verify_affiliate_token(token)
        
        # Get recent clicks with geolocation data (last 24 hours)
        clicks_result = await session.execute(
            text('''
                SELECT 
                    ac.id,
                    ac.ip_address,
                    ac.country_code,
                    ac.country,
                    ac.city,
                    ac.region,
                    ac.latitude,
                    ac.longitude,
                    ac.device_type,
                    ac.browser,
                    ac.os,
                    ac.user_agent,
                    ac.referrer,
                    ac.clicked_at,
                    'click' as activity_type
                FROM affiliate_clicks ac
                WHERE ac.affiliate_id = :affiliate_id
                AND ac.clicked_at >= NOW() - INTERVAL '24 hours'
                ORDER BY ac.clicked_at DESC
                LIMIT :limit
            '''),
            {'affiliate_id': affiliate_id, 'limit': limit}
        )
        
        activities = []
        for row in clicks_result.mappings().all():
            activity = {
                'id': row['id'],
                'type': 'click',
                'timestamp': row['clicked_at'].isoformat() if row['clicked_at'] else None,
                'location': {
                    'country_code': row['country_code'],
                    'country': row['country'],
                    'city': row['city'],
                    'region': row['region'],
                    'latitude': float(row['latitude']) if row['latitude'] else None,
                    'longitude': float(row['longitude']) if row['longitude'] else None
                },
                'device': {
                    'type': row['device_type'],
                    'browser': row['browser'],
                    'os': row['os'],
                    'user_agent': row['user_agent']
                },
                'referrer': row['referrer']
            }
            activities.append(activity)
        
        # Get recent activities from affiliate_activities table if exists
        try:
            activities_result = await session.execute(
                text('''
                    SELECT 
                        id,
                        activity_type,
                        page_url,
                        page_title,
                        country_code,
                        city,
                        latitude,
                        longitude,
                        metadata,
                        created_at
                    FROM affiliate_activities
                    WHERE affiliate_id = :affiliate_id
                    AND created_at >= NOW() - INTERVAL '24 hours'
                    ORDER BY created_at DESC
                    LIMIT :limit
                '''),
                {'affiliate_id': affiliate_id, 'limit': limit}
            )
            
            for row in activities_result.mappings().all():
                activity = {
                    'id': row['id'],
                    'type': row['activity_type'],
                    'timestamp': row['created_at'].isoformat() if row['created_at'] else None,
                    'page_url': row['page_url'],
                    'page_title': row['page_title'],
                    'location': {
                        'country_code': row['country_code'],
                        'city': row['city'],
                        'latitude': float(row['latitude']) if row['latitude'] else None,
                        'longitude': float(row['longitude']) if row['longitude'] else None
                    },
                    'metadata': row['metadata']
                }
                activities.append(activity)
        except Exception as e:
            # Table might not exist yet
            print(f'Note: affiliate_activities table not available: {str(e)}')
        
        # Sort all activities by timestamp
        activities.sort(key=lambda x: x['timestamp'] or '', reverse=True)
        
        return {'activities': activities[:limit]}
        
    except HTTPException:
        raise
    except Exception as e:
        print(f'Error fetching live tracking data: {str(e)}')
        raise HTTPException(status_code=500, detail='Error fetching live tracking data')
