"""
Example of converting existing routes to use Pydantic validation
"""
from fastapi import APIRouter, Depends, HTTPException
from typing import Dict, Any, List, Optional

# Import the Pydantic models
from models.base import FormModel, UserModel, SubmissionModel

# Import the async service with validation
from services.forms_service_async import AsyncFormsService

# Import the session dependency
from db.database import get_session

# Example 1: Converting a standard route to use Pydantic validation
# Original route:
"""
@router.post("/")
async def create_form(form_data: dict, user=Depends(get_current_user)):
    result = FormsService.create_form(user["uid"], form_data)
    if not result:
        raise HTTPException(status_code=400, detail="Failed to create form")
    return {"form": result}
"""

# Converted route with Pydantic validation:
"""
@router.post("/")
async def create_form(
    form_data: FormModel,  # Use Pydantic model instead of dict
    session = Depends(get_session),
    user = Depends(get_current_user)
):
    # FormModel automatically validates and sanitizes the input
    
    # Convert validated model to dict for database
    form_dict = form_data.model_dump()
    
    # Add user ID to the form data
    form_dict["userId"] = user["uid"]
    
    # Use the async service with validation
    result = await AsyncFormsService.create_form(session, form_dict)
    
    if not result:
        raise HTTPException(status_code=400, detail="Failed to create form")
    return {"form": result}
"""

# Example 2: Using Pydantic for request body validation
"""
# Define a Pydantic model for the request body
from pydantic import BaseModel, Field

class FormUpdateRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    theme: Optional[Dict[str, Any]] = None
    fields: Optional[List[Dict[str, Any]]] = None
    
    # Add validation rules
    @validator('title')
    def validate_title(cls, v):
        if v is not None and len(v) > 100:
            raise ValueError('Title must be less than 100 characters')
        return v

@router.put("/{form_id}")
async def update_form(
    form_id: str,
    form_data: FormUpdateRequest,  # Use the request model
    session = Depends(get_session),
    user = Depends(get_current_user)
):
    # Convert validated model to dict, excluding unset fields
    update_data = form_data.model_dump(exclude_unset=True)
    
    # Use the async service
    result = await AsyncFormsService.update_form(
        session, form_id, user["uid"], update_data
    )
    
    if not result:
        raise HTTPException(
            status_code=404, 
            detail="Form not found or not authorized"
        )
    return {"form": result}
"""

# Example 3: Using FastAPI's automatic validation with Pydantic
"""
@router.post("/submissions/{form_id}")
async def create_submission(
    form_id: str,
    submission: SubmissionModel,  # Use Pydantic model
    session = Depends(get_session)
):
    # FastAPI automatically validates the submission data
    # Any validation errors result in a 422 Unprocessable Entity response
    
    # Convert validated model to dict
    submission_dict = submission.model_dump()
    
    # Add form ID
    submission_dict["formId"] = form_id
    
    # Use the async service
    result = await AsyncSubmissionsService.create_submission(
        session, submission_dict
    )
    
    if not result["success"]:
        raise HTTPException(
            status_code=400, 
            detail=result.get("error", "Failed to create submission")
        )
    
    return {
        "success": True, 
        "submissionId": result["submission"]["id"]
    }
"""

# Key benefits of using Pydantic validation:
# 1. Automatic validation of request data
# 2. Type checking and conversion
# 3. Custom validation rules
# 4. Sanitization of input data
# 5. Better IDE support with type hints
# 6. Clearer API documentation with OpenAPI schema
# 7. Consistent error responses