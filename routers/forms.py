"""
Forms API router using PostgreSQL database
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from typing import Dict, Any, Optional, List
from services.forms_service import FormsService
from services.submissions_service import SubmissionsService
from auth.auth_utils import get_current_user

router = APIRouter(prefix="/api/forms", tags=["forms"])

class FormCreate(BaseModel):
    title: str
    name: Optional[str] = None
    description: Optional[str] = None
    formType: Optional[str] = "simple"
    fields: Optional[Dict[str, Any]] = {}
    theme: Optional[Dict[str, Any]] = {}
    branding: Optional[Dict[str, Any]] = {}
    allowedDomains: Optional[List[str]] = []
    submissionLimit: Optional[int] = 0

class FormUpdate(BaseModel):
    title: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None
    formType: Optional[str] = None
    fields: Optional[Dict[str, Any]] = None
    theme: Optional[Dict[str, Any]] = None
    branding: Optional[Dict[str, Any]] = None
    allowedDomains: Optional[List[str]] = None
    submissionLimit: Optional[int] = None

class PublishStatus(BaseModel):
    publish: Optional[bool] = None

@router.get("/")
async def get_forms(user=Depends(get_current_user), limit: int = 100, offset: int = 0):
    """Get all forms for the current user"""
    forms = FormsService.get_forms_by_user(user["uid"], limit, offset)
    return {"forms": forms}

@router.post("/")
async def create_form(form_data: FormCreate, user=Depends(get_current_user)):
    """Create a new form"""
    result = FormsService.create_form(user["uid"], form_data.dict())
    if not result:
        raise HTTPException(status_code=400, detail="Failed to create form")
    return {"form": result}

@router.get("/{form_id}")
async def get_form(form_id: str, user=Depends(get_current_user)):
    """Get a form by ID"""
    form = FormsService.get_form_by_id(form_id, user["uid"])
    if not form:
        raise HTTPException(status_code=404, detail="Form not found")
    return {"form": form}

@router.put("/{form_id}")
async def update_form(form_id: str, form_data: FormUpdate, user=Depends(get_current_user)):
    """Update a form"""
    result = FormsService.update_form(form_id, user["uid"], form_data.dict(exclude_unset=True))
    if not result:
        raise HTTPException(status_code=404, detail="Form not found or not authorized")
    return {"form": result}

@router.delete("/{form_id}")
async def delete_form(form_id: str, user=Depends(get_current_user)):
    """Delete a form"""
    result = FormsService.delete_form(form_id, user["uid"])
    if not result:
        raise HTTPException(status_code=404, detail="Form not found or not authorized")
    return {"success": True}

@router.post("/{form_id}/publish")
async def toggle_publish(form_id: str, status: PublishStatus, user=Depends(get_current_user)):
    """Toggle or set a form's publish status"""
    result = FormsService.toggle_form_publish(form_id, user["uid"], status.publish)
    if not result["success"]:
        raise HTTPException(status_code=404, detail=result.get("error", "Form not found or not authorized"))
    return result

@router.get("/{form_id}/submissions")
async def get_form_submissions(form_id: str, user=Depends(get_current_user), limit: int = 100, offset: int = 0):
    """Get submissions for a form"""
    submissions = FormsService.get_form_submissions(form_id, user["uid"], limit, offset)
    return {"submissions": submissions}

@router.get("/dashboard/stats")
async def get_dashboard_stats(user=Depends(get_current_user)):
    """Get dashboard statistics for the current user"""
    stats = SubmissionsService.get_dashboard_stats(user["uid"])
    return stats