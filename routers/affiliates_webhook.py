"""
Affiliate webhook handlers for tracking subscription conversions
Handles subscription.active webhook to calculate and record 30% commission
"""

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import text
from pydantic import BaseModel
from typing import Optional
import secrets

router = APIRouter()

class SubscriptionWebhookPayload(BaseModel):
    event: str  # subscription.active
    user_id: str
    subscription_plan: str
    subscription_price: float
    subscription_interval: Optional[str] = 'month'  # 'month' or 'year'
    referral_code: Optional[str] = None

async def get_db_connection():
    """Get database connection from pool"""
    from db.database import get_session
    session = get_session()
    return await session.__anext__()

@router.post('/subscription-webhook')
async def handle_subscription_webhook(payload: SubscriptionWebhookPayload):
    """
    Handle subscription.active webhook
    Calculates 30% commission for affiliate and records conversion
    """
    session = None
    try:
        # Only process if there's a referral code
        if not payload.referral_code:
            return {'success': True, 'message': 'No referral code provided'}
        
        session = await get_db_connection()
        
        # Find affiliate by referral code
        affiliate_result = await session.execute(
            text('''
                SELECT id, affiliate_code, commission_rate 
                FROM affiliates 
                WHERE affiliate_code = :code AND is_active = true
            '''),
            {'code': payload.referral_code}
        )
        affiliate = affiliate_result.mappings().first()
        
        if not affiliate:
            # No affiliate found - this is fine, maybe it's not an affiliate referral
            return {'success': True, 'message': 'No affiliate found for code'}
        
        # Calculate 30% commission (subscription_price * 0.30)
        # Works for both monthly and yearly plans - commission is always 30% of the total price
        commission_rate = float(affiliate['commission_rate']) / 100  # Convert 30.00 to 0.30
        commission_amount = payload.subscription_price * commission_rate
        
        # For yearly plans, the full yearly amount * 30% is the commission
        # Example: $290/year plan = $87 commission (30% of $290)
        # Example: $29/month plan = $8.70 commission (30% of $29)
        
        # Check if conversion already exists for this user
        existing_result = await session.execute(
            text('''
                SELECT id FROM affiliate_conversions 
                WHERE affiliate_id = :affiliate_id AND user_id = :user_id
            '''),
            {
                'affiliate_id': affiliate['id'],
                'user_id': payload.user_id
            }
        )
        existing_conversion = existing_result.fetchone()
        
        if existing_conversion:
            # Already tracked this conversion
            return {'success': True, 'message': 'Conversion already tracked'}
        
        # Create conversion record
        conversion_id = secrets.token_urlsafe(16)
        
        # Store conversion with plan details
        plan_display = f"{payload.subscription_plan} ({payload.subscription_interval}ly)"
        
        await session.execute(
            text('''
                INSERT INTO affiliate_conversions 
                (id, affiliate_id, user_id, affiliate_code, commission_amount, 
                 subscription_plan, status, converted_at)
                VALUES (:id, :affiliate_id, :user_id, :code, :commission, 
                        :plan, 'pending', NOW())
            '''),
            {
                'id': conversion_id,
                'affiliate_id': affiliate['id'],
                'user_id': payload.user_id,
                'code': payload.referral_code,
                'commission': commission_amount,
                'plan': plan_display
            }
        )
        
        # Update affiliate totals
        await session.execute(
            text('''
                UPDATE affiliates 
                SET total_conversions = total_conversions + 1,
                    total_earnings = total_earnings + :commission,
                    updated_at = NOW()
                WHERE id = :affiliate_id
            '''),
            {
                'affiliate_id': affiliate['id'],
                'commission': commission_amount
            }
        )
        
        # Update user's referral_code field if not already set
        await session.execute(
            text('''
                UPDATE users 
                SET referral_code = :code
                WHERE uid = :user_id AND (referral_code IS NULL OR referral_code = '')
            '''),
            {
                'code': payload.referral_code,
                'user_id': payload.user_id
            }
        )
        
        await session.commit()
        
        return {
            'success': True,
            'conversion_id': conversion_id,
            'commission_amount': commission_amount,
            'subscription_plan': plan_display,
            'subscription_price': payload.subscription_price,
            'commission_rate': f"{affiliate['commission_rate']}%",
            'affiliate_id': affiliate['id']
        }
        
    except Exception as e:
        if session:
            await session.rollback()
        print(f'Error processing subscription webhook: {str(e)}')
        raise HTTPException(status_code=500, detail=f'Error processing webhook: {str(e)}')
    finally:
        if session:
            await session.close()

@router.post('/track-signup')
async def track_affiliate_signup(user_id: str, referral_code: str):
    """
    Track when a user signs up with an affiliate referral code
    Called during user registration
    """
    session = None
    try:
        if not referral_code:
            return {'success': True, 'message': 'No referral code'}
        
        session = await get_db_connection()
        
        # Verify affiliate exists
        affiliate_result = await session.execute(
            text('SELECT id FROM affiliates WHERE affiliate_code = :code AND is_active = true'),
            {'code': referral_code}
        )
        affiliate = affiliate_result.fetchone()
        
        if not affiliate:
            return {'success': False, 'message': 'Invalid referral code'}
        
        # Update affiliate signup counter
        await session.execute(
            text('''
                UPDATE affiliates 
                SET total_signups = total_signups + 1,
                    updated_at = NOW()
                WHERE id = :affiliate_id
            '''),
            {'affiliate_id': affiliate['id']}
        )
        
        # Store referral code in user record
        await session.execute(
            text('UPDATE users SET referral_code = :code WHERE uid = :user_id'),
            {'code': referral_code, 'user_id': user_id}
        )
        
        await session.commit()
        
        return {'success': True, 'affiliate_id': affiliate['id']}
        
    except Exception as e:
        if session:
            await session.rollback()
        print(f'Error tracking signup: {str(e)}')
        raise HTTPException(status_code=500, detail='Error tracking signup')
    finally:
        if session:
            await session.close()
