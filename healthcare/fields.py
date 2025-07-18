# healthcare/fields.py
from django.db import models
from django.core.exceptions import ValidationError
from django.core.validators import URLValidator
from security.encryption import AES256Encryption
import json

class EncryptedMixin:
    """Mixin to add encryption/decryption functionality to any field."""
    
    def from_db_value(self, value, expression, connection):
        if value is None:
            return value
        try:
            # Decrypt the value
            encrypted_data = json.loads(value)
            decrypted = AES256Encryption.decrypt(encrypted_data)
            decrypted_str = decrypted.decode('utf-8')
            
            # Convert to appropriate type
            return self.to_python_value(decrypted_str)
        except (json.JSONDecodeError, KeyError, ValueError):
            # Return as-is if not encrypted (for migration compatibility)
            return value
    
    def to_python_value(self, value):
        """Override in subclasses to convert decrypted string to proper type."""
        return value
    
    def get_prep_value(self, value):
        if value is None:
            return value
        # Convert to string then encrypt
        str_value = self.value_to_string(value)
        encrypted = AES256Encryption.encrypt(str_value)
        return json.dumps(encrypted)
    
    def value_to_string(self, value):
        """Convert value to string for encryption."""
        return str(value) if value is not None else ''

class EncryptedCharField(EncryptedMixin, models.TextField):
    """Encrypted CharField stored as TextField"""
    
    def __init__(self, max_length=None, **kwargs):
        # Store max_length for validation but don't pass to TextField
        self.max_length = max_length
        super().__init__(**kwargs)
    
    def to_python_value(self, value):
        return str(value) if value else value

class EncryptedTextField(EncryptedMixin, models.TextField):
    """Encrypted TextField"""
    
    def to_python_value(self, value):
        return str(value) if value else value

class EncryptedIntegerField(EncryptedMixin, models.TextField):
    """Encrypted IntegerField stored as TextField"""
    
    def to_python_value(self, value):
        if value and isinstance(value, str):
            try:
                return int(value)
            except ValueError:
                return None
        return value

class EncryptedDecimalField(EncryptedMixin, models.TextField):
    """Encrypted DecimalField stored as TextField"""
    
    def __init__(self, max_digits=None, decimal_places=None, **kwargs):
        # Store decimal params for validation but don't pass to TextField
        self.max_digits = max_digits
        self.decimal_places = decimal_places
        super().__init__(**kwargs)
    
    def to_python_value(self, value):
        if value and isinstance(value, str):
            try:
                from decimal import Decimal
                return Decimal(value)
            except (ValueError, TypeError):
                return None
        return value

class EncryptedDateField(EncryptedMixin, models.TextField):
    """Encrypted DateField stored as TextField"""
    
    def to_python_value(self, value):
        if value and isinstance(value, str):
            from django.utils.dateparse import parse_date
            return parse_date(value)
        return value
    
    def value_to_string(self, value):
        if value:
            return value.isoformat() if hasattr(value, 'isoformat') else str(value)
        return ''

class EncryptedURLField(EncryptedMixin, models.TextField):
    """Encrypted URLField stored as TextField"""
    
    def __init__(self, max_length=200, **kwargs):
        # Store max_length for validation but don't pass to TextField
        self.max_length = max_length
        super().__init__(**kwargs)
    
    def to_python_value(self, value):
        return str(value) if value else value
    
    def validate(self, value, model_instance):
        super().validate(value, model_instance)
        if value:
            url_validator = URLValidator()
            try:
                url_validator(value)
            except ValidationError:
                raise ValidationError('Enter a valid URL.')

class EncryptedJSONField(EncryptedMixin, models.TextField):
    """Encrypted JSONField stored as TextField"""
    
    def to_python_value(self, value):
        if value and isinstance(value, str):
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return value
        return value
    
    def value_to_string(self, value):
        if value is not None:
            return json.dumps(value)
        return ''
