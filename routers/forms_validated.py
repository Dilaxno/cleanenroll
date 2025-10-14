"""
Forms router with Pydantic validation
"""
from fastapi import APIRouter, Depends, HTTPException, status
from typing import Dict, Any, List
from sqlalchemy.ext.asyncio import AsyncSession

from ..db.database import get_session
from ..services.forms_service_async import AsyncFormsService
from ..models.base import FormModel

router = APIRouter(prefix="/api/forms", tags=["forms"])

@router.get("/")
async def get_forms(
    user_id: str,
    limit: int = 100, 
    offset: int = 0,
    session: AsyncSession = Depends(get_session)
):
    """Get forms for a user with pagination"""
    forms = await AsyncFormsService.get_forms_by_user(session, user_id, limit, offset)
    return {"forms": forms}

@router.get("/{form_id}")
async def get_form(
    form_id: str,
    user_id: str = None,
    session: AsyncSession = Depends(get_session)
):
    """Get a form by ID"""
    form = await AsyncFormsService.get_form_by_id(session, form_id, user_id)
    if not form:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Form not found"
        )
    return form

@router.post("/")
async def create_form(
    form_data: FormModel,
    session: AsyncSession = Depends(get_session)
):
    """
    Create a new form with Pydantic validation
    
    The FormModel Pydantic model handles:
    - Input validation (field types, required fields)
    - Data sanitization (HTML escaping, string cleaning)
    - Format validation (email, URLs, etc.)
    """
    # Convert Pydantic model to dict
    form_dict = form_data.model_dump()
    
    # Create form with validation
    form = await AsyncFormsService.create_form(session, form_dict)
    
    # Check for validation errors
    if form and "errors" in form:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=form["errors"]
        )
        
    return form

@router.put("/{form_id}")
async def update_form(
    form_id: str,
    form_data: FormModel,
    user_id: str,
    session: AsyncSession = Depends(get_session)
):
    """
    Update a form with Pydantic validation
    
    All input is validated and sanitized through the FormModel
    """
    # Convert Pydantic model to dict
    form_dict = form_data.model_dump()
    
    # Update form with validation
    form = await AsyncFormsService.update_form(session, form_id, user_id, form_dict)
    
    if not form:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Form not found or you don't have permission to update it"
        )
        
    # Check for validation errors
    if "errors" in form:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=form["errors"]
        )
        
    return form