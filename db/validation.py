"""
Database validation module using Pydantic models
"""
from typing import Dict, Any, Type, TypeVar, Optional, Union, Callable, Awaitable
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.validators import (
    validate_user, validate_form, validate_submission, validate_analytics,
    sanitize_for_db
)
from ..models.base import UserModel, FormModel, SubmissionModel, AnalyticsModel

async def validate_and_execute(
    data: Dict[str, Any],
    validator_func: Callable,
    db_operation: Callable[[AsyncSession, Dict[str, Any]], Awaitable[Any]],
    session: AsyncSession
) -> Any:
    """
    Validate input data and execute database operation if validation passes
    
    Args:
        data: Input data to validate
        validator_func: Function to validate the data
        db_operation: Async function that performs the database operation
        session: SQLAlchemy async session
        
    Returns:
        Result of the database operation
        
    Raises:
        HTTPException: If validation fails
    """
    # Validate the data
    is_valid, result = validator_func(data)
    
    if not is_valid:
        # If validation failed, raise an HTTP exception with the validation errors
        raise HTTPException(status_code=422, detail={"errors": result})
    
    # Convert validated model to dict for database operation
    db_data = sanitize_for_db(result)
    
    # Execute the database operation
    return await db_operation(session, db_data)

# Specific validation wrappers for each entity type
async def validate_and_save_user(
    session: AsyncSession, 
    user_data: Dict[str, Any],
    db_operation: Callable[[AsyncSession, Dict[str, Any]], Awaitable[Any]]
) -> Any:
    """Validate and save user data"""
    return await validate_and_execute(user_data, validate_user, db_operation, session)

async def validate_and_save_form(
    session: AsyncSession, 
    form_data: Dict[str, Any],
    db_operation: Callable[[AsyncSession, Dict[str, Any]], Awaitable[Any]]
) -> Any:
    """Validate and save form data"""
    return await validate_and_execute(form_data, validate_form, db_operation, session)

async def validate_and_save_submission(
    session: AsyncSession, 
    submission_data: Dict[str, Any],
    db_operation: Callable[[AsyncSession, Dict[str, Any]], Awaitable[Any]]
) -> Any:
    """Validate and save submission data"""
    return await validate_and_execute(submission_data, validate_submission, db_operation, session)

async def validate_and_save_analytics(
    session: AsyncSession, 
    analytics_data: Dict[str, Any],
    db_operation: Callable[[AsyncSession, Dict[str, Any]], Awaitable[Any]]
) -> Any:
    """Validate and save analytics data"""
    return await validate_and_execute(analytics_data, validate_analytics, db_operation, session)