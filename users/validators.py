import re
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

def validate_npi_number(value):
    """Validate NPI number format."""
    if not re.match(r'^\d{10}$', value):
        raise ValidationError(_('NPI number must be exactly 10 digits.'))

def validate_medical_license(value):
    """Validate medical license format."""
    if len(value) < 4:
        raise ValidationError(_('Medical license number is too short.'))
    
    # Add more specific validation based on requirements
    if not re.match(r'^[A-Z0-9]+$', value.upper()):
        raise ValidationError(_('Medical license must contain only letters and numbers.'))

def validate_phone_number(value):
    """Validate phone number format."""
    # Remove common formatting characters
    cleaned = re.sub(r'[\s\-\(\)\.]+', '', value)
    
    # Check if it's a valid format
    if not re.match(r'^\+?1?\d{10,14}$', cleaned):
        raise ValidationError(_('Please enter a valid phone number.'))

def validate_regulatory_id(value):
    """Validate regulatory ID format for pharmaceutical companies."""
    if len(value) < 3:
        raise ValidationError(_('Regulatory ID is too short.'))

def validate_strong_password(password):
    """Validate password strength beyond Django's default."""
    if len(password) < 12:
        raise ValidationError(_('Password must be at least 12 characters long.'))
    
    if not re.search(r'[A-Z]', password):
        raise ValidationError(_('Password must contain at least one uppercase letter.'))
    
    if not re.search(r'[a-z]', password):
        raise ValidationError(_('Password must contain at least one lowercase letter.'))
    
    if not re.search(r'\d', password):
        raise ValidationError(_('Password must contain at least one digit.'))
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        raise ValidationError(_('Password must contain at least one special character.'))

def validate_hipaa_compliant_data(value):
    """Validate that data doesn't contain obvious PHI violations."""
    # This is a basic check - in production, you'd want more sophisticated validation
    sensitive_patterns = [
        r'\b\d{3}-\d{2}-\d{4}\b',  # SSN pattern
        r'\b\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b',  # Credit card pattern
    ]
    
    for pattern in sensitive_patterns:
        if re.search(pattern, str(value)):
            raise ValidationError(_('This field appears to contain sensitive information that should not be stored here.'))

