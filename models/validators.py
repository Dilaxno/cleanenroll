"""
Utility functions for data validation and sanitization using Pydantic models
"""
from typing import Dict, Any, Type, TypeVar, Optional, Union, List
from pydantic import BaseModel, ValidationError

from .base import UserModel, FormModel, SubmissionModel, AnalyticsModel

T = TypeVar('T', bound=BaseModel)

def validate_data(data: Dict[str, Any], model_class: Type[T]) -> tuple[bool, Union[T, Dict[str, Any]]]:
    """
    Validate and sanitize input data using a Pydantic model
    
    Args:
        data: The input data to validate
        model_class: The Pydantic model class to use for validation
        
    Returns:
        Tuple of (is_valid, result) where:
        - is_valid: Boolean indicating if validation passed
        - result: Either the validated model instance or a dict of validation errors
    """
    try:
        # Validate and sanitize the data
        validated_data = model_class(**data)
        return True, validated_data
    except ValidationError as e:
        # Return validation errors
        return False, e.errors()

def sanitize_for_db(model_instance: BaseModel) -> Dict[str, Any]:
    """
    Convert a validated Pydantic model to a dictionary suitable for database insertion
    
    Args:
        model_instance: A validated Pydantic model instance
        
    Returns:
        Dictionary with sanitized data ready for database insertion
    """
    # Convert to dict, excluding None values
    return model_instance.model_dump(exclude_none=True)

# Specific validation functions for each entity type
def validate_user(user_data: Dict[str, Any]) -> tuple[bool, Union[UserModel, Dict[str, Any]]]:
    """Validate and sanitize user data"""
    return validate_data(user_data, UserModel)

def validate_form(form_data: Dict[str, Any]) -> tuple[bool, Union[FormModel, Dict[str, Any]]]:
    """Validate and sanitize form data"""
    return validate_data(form_data, FormModel)

def validate_submission(submission_data: Dict[str, Any]) -> tuple[bool, Union[SubmissionModel, Dict[str, Any]]]:
    """Validate and sanitize form submission data"""
    return validate_data(submission_data, SubmissionModel)

def validate_analytics(analytics_data: Dict[str, Any]) -> tuple[bool, Union[AnalyticsModel, Dict[str, Any]]]:
    """Validate and sanitize analytics data"""
    return validate_data(analytics_data, AnalyticsModel)