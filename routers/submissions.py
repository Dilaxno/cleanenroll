"""
Submissions API router using PostgreSQL database
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from typing import Dict, Any, Optional
from services.submissions_service import SubmissionsService
from auth.auth_utils import get_current_user, get_request_metadata

router = APIRouter(prefix="/api/submissions", tags=["submissions"])

class SubmissionCreate(BaseModel):
    data: Dict[str, Any]

@router.post("/{form_id}")
async def create_submission(form_id: str, submission: SubmissionCreate, request: Request):
    """Create a new submission for a form"""
    # Get request metadata
    metadata = get_request_metadata(request)
    
    result = SubmissionsService.create_submission(form_id, submission.data, metadata)
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result.get("error", "Failed to create submission"))
    
    return {"success": True, "submissionId": result["submission"]["id"]}

@router.get("/{submission_id}")
async def get_submission(submission_id: str, user=Depends(get_current_user)):
    """Get a submission by ID (requires form ownership)"""
    submission = SubmissionsService.get_submission(submission_id, user["uid"])
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found or not authorized")
    
    return {"submission": submission}

@router.delete("/{submission_id}")
async def delete_submission(submission_id: str, user=Depends(get_current_user)):
    """Delete a submission (requires form ownership)"""
    result = SubmissionsService.delete_submission(submission_id, user["uid"])
    if not result:
        raise HTTPException(status_code=404, detail="Submission not found or not authorized")
    
    return {"success": True}