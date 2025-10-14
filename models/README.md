# Pydantic Validation Implementation Guide

This guide explains how to use the Pydantic validation system implemented in the CleanEnroll backend.

## Quick Start

To use Pydantic validation in your routes:

1. Import the Pydantic models in your routes
2. Use the async forms service for database operations
3. Let FastAPI and Pydantic handle the validation automatically

## Example Implementation

```python
from fastapi import APIRouter, Depends, HTTPException
from models.base import FormModel
from services.forms_service_async import AsyncFormsService

router = APIRouter()
forms_service = AsyncFormsService()

@router.post("/forms")
async def create_form(form_data: FormModel):
    # FastAPI automatically validates the input using the FormModel
    # Any validation errors will be returned as HTTP 422 responses
    
    try:
        # The form_data is already validated and sanitized
        result = await forms_service.create_form(form_data)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
```

## Key Components

1. **Pydantic Models** (`models/base.py`):
   - Define data structures with validation rules
   - Automatically sanitize string inputs
   - Enforce type checking and constraints

2. **Validation Utilities** (`models/validators.py`):
   - Helper functions for validation and sanitization
   - Convert between Pydantic models and database dictionaries

3. **Database Validation Layer** (`db/validation.py`):
   - Validate data before database operations
   - Sanitize inputs to prevent SQL injection

4. **Async Services** (`services/forms_service_async.py`):
   - Use Pydantic models for input validation
   - Handle database operations with validated data

## Benefits

- Automatic input validation and sanitization
- Type safety and better IDE support
- Protection against SQL injection and XSS attacks
- Cleaner code with separation of concerns

## Available Routes

The validated forms API is available at `/api/v1/forms` endpoints.