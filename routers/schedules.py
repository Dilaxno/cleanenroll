import logging
from fastapi import APIRouter, HTTPException, Query, Request
from db.database import async_session_maker
from sqlalchemy import text
from typing import Optional, List, Dict, Any
from datetime import datetime
import json

logger = logging.getLogger("backend.schedules")

router = APIRouter(prefix="/api/schedules", tags=["schedules"])


@router.get("/user/{user_id}")
async def get_user_schedules(
    user_id: str,
    request: Request,
    from_date: Optional[str] = Query(None, description="Filter from date (ISO format)"),
    to_date: Optional[str] = Query(None, description="Filter to date (ISO format)")
):
    """
    Get all calendar/date submissions for a user's forms.
    Returns submissions that contain date or calendar fields.
    """
    if not user_id:
        raise HTTPException(status_code=400, detail="Missing user_id")
    
    if async_session_maker is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    
    try:
        # Parse date filters if provided
        from_ts = None
        to_ts = None
        
        if from_date:
            try:
                from_ts = datetime.fromisoformat(from_date.replace('Z', '+00:00'))
            except Exception:
                logger.warning("Invalid from_date format: %s", from_date)
        
        if to_date:
            try:
                to_ts = datetime.fromisoformat(to_date.replace('Z', '+00:00'))
            except Exception:
                logger.warning("Invalid to_date format: %s", to_date)
        
        async with async_session_maker() as session:
            # Get all submissions for user's forms with date/calendar fields
            query = """
                SELECT 
                    s.id,
                    s.form_id,
                    s.data,
                    s.submitted_at,
                    f.name as form_name,
                    f.title as form_title,
                    f.fields
                FROM submissions s
                INNER JOIN forms f ON s.form_id = f.id
                WHERE f.user_id = :user_id
            """
            params = {"user_id": user_id}
            
            if from_ts:
                query += " AND s.submitted_at >= :from_date"
                params["from_date"] = from_ts
            
            if to_ts:
                query += " AND s.submitted_at <= :to_date"
                params["to_date"] = to_ts
            
            query += " ORDER BY s.submitted_at DESC LIMIT 500"
            
            result = await session.execute(text(query), params)
            rows = result.mappings().all()
            
            # Process submissions to extract calendar events
            events = []
            
            for row in rows:
                submission_data = row.get('data') or {}
                if isinstance(submission_data, str):
                    try:
                        submission_data = json.loads(submission_data)
                    except:
                        submission_data = {}
                
                form_fields = row.get('fields') or []
                if isinstance(form_fields, str):
                    try:
                        form_fields = json.loads(form_fields)
                    except:
                        form_fields = []
                
                # Extract date/calendar/time fields including zoom meetings
                for field in form_fields:
                    field_type = field.get('type', '')
                    field_id = field.get('id', '')
                    field_label = field.get('label', '') or field.get('question', '') or 'Untitled Field'
                    
                    if field_type in ['date', 'age', 'calendar', 'time']:
                        # Get the value from submission data (submissions use field labels as keys, not IDs)
                        field_value = submission_data.get(field_label)
                        
                        if field_value:
                            # Parse date value
                            event_date = None
                            event_time = None
                            zoom_meeting_data = None
                            
                                
                                if zoom_date:
                                    event_date = zoom_date
                                if zoom_time:
                                    event_time = zoom_time
                            elif isinstance(field_value, str):
                                # Try to parse ISO date or datetime
                                try:
                                    dt = datetime.fromisoformat(field_value.replace('Z', '+00:00'))
                                    event_date = dt.date().isoformat()
                                    if dt.hour != 0 or dt.minute != 0:
                                        event_time = dt.time().isoformat()
                                except:
                                    # If it's just a date string like "2024-01-15"
                                    event_date = field_value
                            
                            if event_date:
                                event_obj = {
                                    "id": f"{row['id']}_{field_id}",
                                    "submission_id": row['id'],
                                    "form_id": row['form_id'],
                                    "form_name": row['form_name'] or row['form_title'] or 'Untitled Form',
                                    "field_label": field_label,
                                    "field_type": field_type,
                                    "date": event_date,
                                    "time": event_time,
                                    "submitted_at": row['submitted_at'].isoformat() if row.get('submitted_at') else None,
                                    "all_data": submission_data
                                }
                                
                                # Add zoom meeting details if available
                                if zoom_meeting_data:
                                    event_obj["zoom_meeting"] = {
                                        "topic": zoom_meeting_data.get('topic', ''),
                                        "duration": zoom_meeting_data.get('duration', 30),
                                        "agenda": zoom_meeting_data.get('agenda', ''),
                                        "join_url": zoom_meeting_data.get('join_url', ''),
                                        "meeting_id": zoom_meeting_data.get('id', '')
                                    }
                                
                                events.append(event_obj)
            
            return {
                "events": events,
                "total": len(events)
            }
    
    except Exception as e:
        logger.exception("Failed to fetch user schedules")
        raise HTTPException(status_code=500, detail=f"Failed to fetch schedules: {str(e)}")
