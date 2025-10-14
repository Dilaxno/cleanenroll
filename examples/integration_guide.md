# Integrating Pydantic Validation with Existing Services

This guide explains how to integrate the Pydantic validation system with your existing CleanEnroll services.

## Quick Integration Steps

1. **Import Pydantic Models in Your Routes**
   ```python
   from models.base import FormModel, UserModel, SubmissionModel
   ```

2. **Use Async Forms Service for Database Operations**
   ```python
   from services.forms_service_async import AsyncFormsService
   
   # Use the service in your route
   result = await AsyncFormsService.create_form(session, form_data)
   ```

3. **Let FastAPI Handle Validation Automatically**
   ```python
   @router.post("/forms")
   async def create_form(form_data: FormModel):
       # form_data is already validated and sanitized
       # ...
   ```

## Integration with Existing Services

### Step 1: Replace Dict Parameters with Pydantic Models

Change your route parameters from dictionaries to Pydantic models:

```python
# Before
async def create_form(form_data: dict):

# After
async def create_form(form_data: FormModel):
```

### Step 2: Use Async Database Session

Update your routes to use the async session:

```python
from db.database import get_session

@router.post("/forms")
async def create_form(
    form_data: FormModel,
    session = Depends(get_session)
):
    # ...
```

### Step 3: Call Async Service Methods

Replace direct database calls with async service methods:

```python
# Before
result = FormsService.create_form(user_id, form_data)

# After
result = await AsyncFormsService.create_form(session, form_data.model_dump())
```

## Validation Layer

The validation system works in three layers:

1. **FastAPI Request Validation**: Validates incoming requests against Pydantic models
2. **Service Layer Validation**: Additional business logic validation in services
3. **Database Layer Validation**: Final sanitization before database operations

## Example: Complete Route Integration

```python
@router.post("/forms")
async def create_form(
    form_data: FormModel,
    session: AsyncSession = Depends(get_session),
    user = Depends(get_current_user)
):
    # Add user ID to form data
    form_dict = form_data.model_dump()
    form_dict["userId"] = user["uid"]
    
    # Create form with validation
    result = await AsyncFormsService.create_form(session, form_dict)
    
    if not result:
        raise HTTPException(status_code=400, detail="Failed to create form")
    
    return {"form": result}
```

## Testing Your Integration

1. Start the server with your updated routes
2. Access the new validated endpoints at `/api/v1/forms`
3. Try submitting invalid data to see automatic validation errors