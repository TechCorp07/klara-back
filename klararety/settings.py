"""
Consolidated settings.py for Klararety platform.
Includes all components and security configurations.
"""
import os
import base64
from pathlib import Path
from datetime import timedelta
import environ
from corsheaders.defaults import default_headers
from cryptography.fernet import Fernet

# Build paths inside the project
BASE_DIR = Path(__file__).resolve().parent.parent
environ.Env.read_env(os.path.join(BASE_DIR, '.env'))

env = environ.Env()

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = env('SECRET_KEY', default='django-insecure-change-in-production')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = env.bool('DEBUG', default=True)

ALLOWED_HOSTS = env.list('ALLOWED_HOSTS', default=['api.klararety.com', 'klararety.com', 'localhost', '127.0.0.1'])

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    
    # Third-party apps
    #'django_csp',  # Content Security Policy
    'rest_framework',
    'corsheaders',
    'channels',
    'django_filters',
    'drf_yasg',
    'django_otp',
    'django_otp.plugins.otp_totp',
    'django_otp.plugins.otp_static',
    'django_extensions',
    'django_celery_beat',
    'sslserver',
    
    # Klararety apps
    'users',
    'audit',
    'wearables',
    'fhir',
    'community',
    'security',
    'medication',
    'healthcare',
    'telemedicine',
    'communication',
    'reports',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'debug_logging_middleware.DebugLoggingMiddleware',
    'security.middleware.SecurityResponseMiddleware',  
    'users.jwt_middleware.SecurityHeadersMiddleware',  # security headers
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'security.middleware.SecurityMonitoringMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'users.jwt_middleware.JWTAuthenticationMiddleware', 
    'users.jwt_middleware.PharmaceuticalTenantMiddleware',
    'users.session_manager.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django_otp.middleware.OTPMiddleware',  # 2FA middleware
    'audit.middleware.AuditMiddleware',  # Audit logging
    'community.middleware.AccessibilityMiddleware',  # Community accessibility
    'community.middleware.PHIProtectionMiddleware',  # PHI protection
]

ROOT_URLCONF = 'klararety.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'klararety.wsgi.application'
ASGI_APPLICATION = 'klararety.routing.application'

# Custom user model
AUTH_USER_MODEL = 'users.User'

# Database configuration
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': env('DB_NAME', default='klararety_back'),
        'USER': env('DB_USER', default='postgres'),
        'PASSWORD': env('DB_PASSWORD', default=''),
        'HOST': env('DB_HOST', default='localhost'),
        'PORT': env('DB_PORT', default='5432'),
"""         'OPTIONS': {
            'sslmode': 'require',
            'sslcert': env('DB_CLIENT_CERT'),
            'sslkey': env('DB_CLIENT_KEY'),
            'sslrootcert': env('DB_CA_CERT'),
        }, """
        'CONN_MAX_AGE': 60,
        'CONN_HEALTH_CHECKS': True,
    },
}

# Add MongoDB for FHIR resources if needed
if env.bool('USE_MONGODB', default=False):
    DATABASES['mongodb'] = {
        'ENGINE': 'djongo',
        'NAME': env('MONGODB_NAME', default='klararety_fhir'),
        'CLIENT': {
            'host': env('MONGODB_URI', default='mongodb://localhost:27017/klararety_fhir'),
            'username': env('MONGODB_USER', default=''),
            'password': env('MONGODB_PASSWORD', default=''),
            'authSource': env('MONGODB_AUTH_SOURCE', default='admin'),
        }
    }

# Add InfluxDB for time-series data if needed
if env.bool('USE_INFLUXDB', default=False):
    DATABASES['influxdb'] = {
        'URL': env('INFLUXDB_URL', default='http://localhost:8086'),
        'TOKEN': env('INFLUXDB_TOKEN', default=''),
        'ORG': env('INFLUXDB_ORG', default='klararety'),
        'BUCKET': env('INFLUXDB_BUCKET', default='wearable_data'),
    }

# Cache configuration # needed in prod
""" CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': env('REDIS_URL', default='redis://localhost:6379/1'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        }
    }
} """

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
    }
}

# needed in prod
"""
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': env('REDIS_URL'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            'CONNECTION_POOL_KWARGS': {'ssl_cert_reqs': None},
        }
    }
}

# Channels configuration for WebSockets
CHANNEL_LAYERS = {
    'default': {
        'BACKEND': 'channels_redis.core.RedisChannelLayer',
        'CONFIG': {
            'hosts': [env('REDIS_URL', default='redis://localhost:6379/2')],
        },
    },
} """

CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels.layers.InMemoryChannelLayer",
    },
}

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 12,
        }
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = '/static/'
STATIC_ROOT = env('STATIC_ROOT', default=os.path.join(BASE_DIR, 'staticfiles'))
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# Media files
MEDIA_URL = '/media/'
MEDIA_ROOT = env('MEDIA_ROOT', default=os.path.join(BASE_DIR, 'media'))

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
    'users.jwt_auth.JWTAuthenticationBackend',
]

# REST Framework settings
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'users.authentication.SimpleJWTAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20,
    'DEFAULT_FILTER_BACKENDS': [
        'django_filters.rest_framework.DjangoFilterBackend',
        'rest_framework.filters.SearchFilter',
        'rest_framework.filters.OrderingFilter',
    ], # needed in prod
"""     'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle',
        'rest_framework.throttling.ScopedRateThrottle',
    ], """
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/day',
        'user': '1000/day',
        'phi_access': '500/hour',
        'wearable_sync': '100/hour',
    },
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
        'rest_framework.renderers.BrowsableAPIRenderer' if DEBUG else 'rest_framework.renderers.JSONRenderer',
    ],
    # 'EXCEPTION_HANDLER': 'klararety.utils.custom_exception_handler',
}

# CORS settings
CORS_ALLOW_ALL_ORIGINS = DEBUG
CORS_ALLOW_HEADERS = (
    *default_headers,
    "cache-control",
    "x-request-timestamp",
    "pragma",
)

CORS_ALLOWED_ORIGINS = env.list('CORS_ALLOWED_ORIGINS', default=[
    "https://klararety.com",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "https://localhost:8000",   # Your backend
    "https://127.0.0.1:8000",
])

CORS_ALLOWED_ORIGIN_REGEXES = [
    r"^https:\/\/.*\.klararety\.com$",
    r"^https:\/\/klararety\.com$",
]

CSRF_TRUSTED_ORIGINS = env.list('CSRF_TRUSTED_ORIGINS', default=[
    "https://api.klararety.com",
    "http://localhost:3000",
    "https://klararety.com",
    "https://127.0.0.1:8000",
])

CORS_ALLOW_CREDENTIALS = False

# Security settings
# AES-256 encryption key (32 bytes)
#ENCRYPTION_KEY = base64.b64decode(env('ENCRYPTION_KEY_BASE64'))
ENCRYPTION_KEY = base64.b64decode("bKE5DvURUc4WLBgXm6Ss2GZsqgSBZXFdpUHmMD4XqU8=")

SESSION_ENCRYPTION_KEY = os.environ.get('SESSION_ENCRYPTION_KEY', default=None)  # Generate with Fernet.generate_key()
if not SESSION_ENCRYPTION_KEY:
    SESSION_ENCRYPTION_KEY = Fernet.generate_key()
    
SESSION_TIMEOUT_MINUTES = 20
MAX_CONCURRENT_SESSIONS = 5
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = 'DENY'

# Create necessary directories
os.makedirs(os.path.join(BASE_DIR, 'logs'), exist_ok=True)

# HIPAA Audit Logging
HIPAA_LOG_PATH = env('HIPAA_AUDIT_LOG_PATH', default=os.path.join(BASE_DIR, 'logs/hipaa_audit.log'))
os.makedirs(os.path.dirname(HIPAA_LOG_PATH), exist_ok=True)

HIPAA_SETTINGS = {
    'DATA_RETENTION_YEARS': 6,  # Minimum HIPAA requirement
    'PASSWORD_EXPIRY_DAYS': 90,
    'SESSION_TIMEOUT_MINUTES': 30,
    'MAX_LOGIN_ATTEMPTS': 5,
    'ACCOUNT_LOCKOUT_MINUTES': 30,
    'IDENTITY_VERIFICATION_DEADLINE_DAYS': 30,
    'EMERGENCY_ACCESS_TIMEOUT_HOURS': 4,
    'AUDIT_LOG_RETENTION_YEARS': 6,
}

# Email Settings for Notifications
EMAIL_SETTINGS = {
    'ADMIN_NOTIFICATION_EMAIL': 'admin@klararety.com',
    'COMPLIANCE_NOTIFICATION_EMAIL': 'compliance@klararety.com',
    'SUPPORT_EMAIL': 'support@klararety.com',
    'NO_REPLY_EMAIL': 'noreply@klararety.com',
}

# Security Module Configuration
SECURITY_MONITORING_ENABLED = False  # Set to True for production
SECURITY_RATE_LIMITING_ENABLED = True
SECURITY_THREAT_DETECTION_ENABLED = True
SECURITY_BLOCK_SUSPICIOUS_PATTERNS = False  # Set to True for production
SECURITY_AUTO_START_MONITORING = True

# Security Rate Limits
SECURITY_RATE_LIMITS = {
    'requests_per_minute': 200, #60 for production
    'failed_logins_per_hour': 50, #10 for production
    'api_calls_per_minute': 200 #100 for production
}

# Security Alert Recipients
SECURITY_ADMIN_EMAILS = [
    'security@klararety.com',
    'admin@klararety.com'
]

SECURITY_MANAGEMENT_EMAILS = [
    'management@klararety.com'
]

SECURITY_ESCALATION_EMAILS = [
    'escalation@klararety.com'
]

# Compliance Report Recipients
COMPLIANCE_MANAGEMENT_EMAILS = [
    'compliance@klararety.com'
]

# Data Retention Periods (in days)
SECURITY_THREAT_RETENTION_DAYS = 365
SECURITY_INCIDENT_RETENTION_DAYS = 2190  # 6 years for HIPAA
NETWORK_MONITOR_RETENTION_DAYS = 90
FILE_MONITOR_RETENTION_DAYS = 90

# Vulnerability scanning settings
SECURITY_SCAN_OUTPUT_DIR = os.path.join(BASE_DIR, 'security_scans')
os.makedirs(SECURITY_SCAN_OUTPUT_DIR, exist_ok=True)
ZAP_API_KEY = env('ZAP_API_KEY', default='')
ZAP_PROXY_URL = env('ZAP_PROXY_URL', default='http://localhost:8080')

# Security Settings
SECURITY_SETTINGS = {
    'ENABLE_2FA_REQUIREMENT': False,  # Set to True to require 2FA for all users
    'ENABLE_IP_RESTRICTION': False,   # Set to True to enable IP-based restrictions
    'ENABLE_DEVICE_TRACKING': True,   # Track user devices for security
    'ENABLE_SUSPICIOUS_ACTIVITY_DETECTION': True,
}

# Communication settings
COMMUNICATION_SETTINGS = {
    'ENABLE_REAL_TIME_CHAT': env.bool('ENABLE_REAL_TIME_CHAT', default=True),
    'MAX_MESSAGE_LENGTH': env.int('MAX_MESSAGE_LENGTH', default=5000),
    'MESSAGE_RETENTION_DAYS': env.int('MESSAGE_RETENTION_DAYS', default=2555),  # 7 years for HIPAA
    'ENABLE_MESSAGE_ENCRYPTION': env.bool('ENABLE_MESSAGE_ENCRYPTION', default=True),
    'CRITICAL_ALERT_CHANNELS': ['email', 'sms', 'push', 'smartwatch'],
    'AUTO_ARCHIVE_CONVERSATIONS': env.bool('AUTO_ARCHIVE_CONVERSATIONS', default=True),
}

# Logging configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
        'hipaa': {
            'format': '{asctime} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
        'file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join(BASE_DIR, 'logs', 'klararety.log'),
            'formatter': 'verbose',
            'maxBytes': 10485760,  # 10MB
            'backupCount': 10,
        },
        'auth_file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': os.path.join(BASE_DIR, 'logs', 'auth.log'),
        },
        'security_file': {
            'level': 'WARNING',
            'class': 'logging.FileHandler',
            'filename': os.path.join(BASE_DIR, 'logs', 'security.log'),
        },
        'audit_file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join(BASE_DIR, 'logs', 'audit.log'),
            'formatter': 'verbose',
            'maxBytes': 10485760,  # 10MB
            'backupCount': 10,
        },
        'hipaa_file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': HIPAA_LOG_PATH,
            'formatter': 'hipaa',
            'maxBytes': 10485760,  # 10MB
            'backupCount': 10,
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': True,
        },
        'security': {
            'handlers': ['console', 'security_file'],
            'level': 'WARNING',
            'propagate': True,
        },
        'audit': {
            'handlers': ['console', 'audit_file'],
            'level': 'INFO',
            'propagate': False,
        },
        'hipaa_audit': {
            'handlers': ['hipaa_file'],
            'level': 'INFO',
            'propagate': False,
        },
        'fhir': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': True,
        },
        'community': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': True,
        },
        'wearables': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': True,
        },
        'users': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': True,
        },
        'users.jwt_auth': {
            'handlers': ['auth_file'],
            'level': 'INFO',
            'propagate': True,
        },
        'healthcare.consent': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': True,
        },
        'users.jwt_middleware': {
            'handlers': ['security_file'],
            'level': 'WARNING',
            'propagate': True,
        },
    },
}

# Swagger settings
SWAGGER_SETTINGS = {
    'DEFAULT_INFO': 'klararety.urls.api_info',
    'SECURITY_DEFINITIONS': {
        'Bearer': {
            'type': 'apiKey',
            'name': 'Authorization',
            'in': 'header'
        }
    },
    'USE_SESSION_AUTH': False,
    'PERSIST_AUTH': True,
    'REFETCH_SCHEMA_WITH_AUTH': True,
    'REFETCH_SCHEMA_ON_LOGOUT': True,
    'DEFAULT_MODEL_RENDERING': 'model',
    'TAGS_SORTER': 'alpha',
    'OPERATIONS_SORTER': 'alpha',
    'DEFAULT_GENERATOR_CLASS': 'drf_yasg.generators.OpenAPISchemaGenerator',
}

# FHIR settings
FHIR_SERVER_URL = env('FHIR_SERVER_URL', default='https://api.klararety.com/api/fhir/')
FHIR_VERSION = 'R4'

# Wearable integration settings
WEARABLE_DATA_SYNC_INTERVAL = env.int('WEARABLE_DATA_SYNC_INTERVAL', default=300)
WITHINGS_CLIENT_ID = env('WITHINGS_CLIENT_ID', default='')
WITHINGS_CLIENT_SECRET = env('WITHINGS_CLIENT_SECRET', default='')
WITHINGS_CALLBACK_URL = env('WITHINGS_REDIRECT_URI', default='')

# Email Configuration
EMAIL_BACKEND = env('EMAIL_BACKEND', default='django.core.mail.backends.console.EmailBackend')
EMAIL_HOST = env('EMAIL_HOST', default='localhost')
EMAIL_PORT = env.int('EMAIL_PORT', default=587)
EMAIL_USE_TLS = env.bool('EMAIL_USE_TLS', default=True)
EMAIL_HOST_USER = env('EMAIL_HOST_USER', default='')
EMAIL_HOST_PASSWORD = env('EMAIL_HOST_PASSWORD', default='')
EMAIL_NOTIFICATIONS_ENABLED = env.bool('EMAIL_NOTIFICATIONS_ENABLED', default=False)

# Telemedicine settings
ZOOM_API_KEY = env('ZOOM_API_KEY', default='')
ZOOM_API_SECRET = env('ZOOM_API_SECRET', default='')
ZOOM_WEBHOOK_SECRET = env('ZOOM_WEBHOOK_SECRET', default='')

# Microsoft Teams settings (if used)
MS_TEAMS_CLIENT_ID = env('MS_TEAMS_CLIENT_ID', default='')
MS_TEAMS_CLIENT_SECRET = env('MS_TEAMS_CLIENT_SECRET', default='')
MS_TEAMS_TENANT_ID = env('MS_TEAMS_TENANT_ID', default='')

# Cisco Webex settings (if used)
WEBEX_API_TOKEN = env('WEBEX_API_TOKEN', default='')

# SMS notification configuration
SMS_ENABLED = env.bool('SMS_ENABLED', default=False)
SMS_PROVIDER = env('SMS_PROVIDER', default='twilio')  # Options: 'twilio', 'vonage', 'aws_sns'

# Twilio SMS configuration (if SMS_PROVIDER = 'twilio')
TWILIO_ACCOUNT_SID = env('TWILIO_ACCOUNT_SID', default='')
TWILIO_AUTH_TOKEN = env('TWILIO_AUTH_TOKEN', default='')
TWILIO_PHONE_NUMBER = env('TWILIO_PHONE_NUMBER', default='')

# Telemedicine notification timing (in hours before appointment)
REMINDER_SEND_HOURS = env.int('REMINDER_SEND_HOURS', default=24)
REMINDER_SMS_HOURS = env.int('REMINDER_SMS_HOURS', default=2)

# Frontend URL for notifications
FRONTEND_URL = env('REACT_HOST', default='https://klararety.com')

# No-show policy configuration
NOSHOW_GRACE_PERIOD_MINUTES = env.int('NOSHOW_GRACE_PERIOD_MINUTES', default=15)
MARK_NOSHOW_AUTOMATICALLY = env.bool('MARK_NOSHOW_AUTOMATICALLY', default=True)

# Video recording configuration
DEFAULT_RECORDING_ENABLED = env.bool('DEFAULT_RECORDING_ENABLED', default=False)
RECORDING_REQUIRES_CONSENT = env.bool('RECORDING_REQUIRES_CONSENT', default=True)
RECORDING_RETENTION_DAYS = env.int('RECORDING_RETENTION_DAYS', default=90)

# Scheduling configuration
MIN_APPOINTMENT_MINUTES = env.int('MIN_APPOINTMENT_MINUTES', default=15)
DEFAULT_APPOINTMENT_MINUTES = env.int('DEFAULT_APPOINTMENT_MINUTES', default=30)
BUFFER_BETWEEN_APPOINTMENTS_MINUTES = env.int('BUFFER_BETWEEN_APPOINTMENTS_MINUTES', default=5)
MAX_FUTURE_DAYS_SCHEDULING = env.int('MAX_FUTURE_DAYS_SCHEDULING', default=90)

# AI Integration Settings
CLAUDE_API_KEY = env('CLAUDE_API_KEY', default='')
CLAUDE_MODEL = env('CLAUDE_MODEL', default='claude-3-opus-20240229')
CLAUDE_MAX_TOKENS = env.int('CLAUDE_MAX_TOKENS', default=4000)

# Enable AI features if Claude API key is available
AI_FEATURES_ENABLED = bool(CLAUDE_API_KEY)
# Add to settings.py
SUPPORT_EMAIL = env('SUPPORT_EMAIL', default='support@klararety.com')

# JWT Configuration
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', SECRET_KEY)  # Use dedicated key in production
JWT_ACCESS_TOKEN_LIFETIME = 15  # minutes
JWT_REFRESH_TOKEN_LIFETIME = 24  # hours
JWT_ALGORITHM = 'HS256'

# Pharmaceutical Tenant Configuration
ENABLE_MULTI_TENANT = True
DEFAULT_TENANT_FEATURES = {
    'rare_disease_tracking': True,
    'medication_adherence': True,
    'family_history': True,
    'research_participation': True,
    'ehr_integration': True,
}

# Audit & Compliance
AUDIT_LOG_RETENTION_DAYS = 2555  # 7 years for pharmaceutical research
ENABLE_COMPREHENSIVE_AUDIT = True
FDA_COMPLIANCE_MODE = True
