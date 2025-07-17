import requests
import json
import logging
from datetime import datetime, timedelta
from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)

def exchange_code(code):
    """Exchange authorization code for tokens."""
    # Check if settings are configured
    if not hasattr(settings, 'GOOGLE_FIT_CLIENT_ID') or not settings.GOOGLE_FIT_CLIENT_ID:
        logger.error("Google Fit API credentials not configured")
        return None
        
    token_url = 'https://oauth2.googleapis.com/token'
    token_data = {
        'code': code,
        'client_id': settings.GOOGLE_FIT_CLIENT_ID,
        'client_secret': settings.GOOGLE_FIT_CLIENT_SECRET,
        'redirect_uri': f"{settings.BASE_URL}/api/wearables/callback/google_fit/",
        'grant_type': 'authorization_code'
    }
    
    try:
        response = requests.post(token_url, data=token_data)
        response_data = response.json()
        
        if response.status_code != 200:
            logger.error(f"Google Fit token exchange failed: {response_data}")
            return None
        
        return {
            'access_token': response_data.get('access_token'),
            'refresh_token': response_data.get('refresh_token'),
            'expires_in': response_data.get('expires_in', 3600),
            'scope': response_data.get('scope')
        }
    
    except Exception as e:
        logger.error(f"Error exchanging Google Fit code: {str(e)}")
        return None

def refresh_token(integration):
    """Refresh Google Fit access token."""
    # Check if settings are configured
    if not hasattr(settings, 'GOOGLE_FIT_CLIENT_ID') or not settings.GOOGLE_FIT_CLIENT_ID:
        logger.error("Google Fit API credentials not configured")
        return False
    
    token_url = 'https://oauth2.googleapis.com/token'
    token_data = {
        'client_id': settings.GOOGLE_FIT_CLIENT_ID,
        'client_secret': settings.GOOGLE_FIT_CLIENT_SECRET,
        'refresh_token': integration.refresh_token,
        'grant_type': 'refresh_token'
    }
    
    try:
        response = requests.post(token_url, data=token_data)
        response_data = response.json()
        
        if response.status_code != 200:
            logger.error(f"Google Fit token refresh failed: {response_data}")
            return False
        
        # Update integration with new tokens
        integration.access_token = response_data.get('access_token')
        # Only update refresh token if a new one is provided
        if 'refresh_token' in response_data:
            integration.refresh_token = response_data.get('refresh_token')
        integration.token_expiry = timezone.now() + timedelta(seconds=response_data.get('expires_in', 3600))
        integration.save()
        
        return True
    
    except Exception as e:
        logger.error(f"Error refreshing Google Fit token: {str(e)}")
        return False

def fetch_steps(integration, start_time, end_time):
    """Fetch step count data from Google Fit."""
    if not integration.is_connected():
        logger.error("Google Fit integration not connected")
        return None
    
    url = 'https://www.googleapis.com/fitness/v1/users/me/dataset:aggregate'
    headers = {
        'Authorization': f'Bearer {integration.access_token}',
        'Content-Type': 'application/json'
    }
    
    body = {
        "aggregateBy": [{
            "dataTypeName": "com.google.step_count.delta",
            "dataSourceId": "derived:com.google.step_count.delta:com.google.android.gms:estimated_steps"
        }],
        "bucketByTime": { "durationMillis": 86400000 },  # Daily buckets
        "startTimeMillis": int(start_time.timestamp() * 1000),
        "endTimeMillis": int(end_time.timestamp() * 1000)
    }
    
    try:
        response = requests.post(url, headers=headers, json=body)
        if response.status_code != 200:
            logger.error(f"Google Fit steps fetch failed: {response.text}")
            return None
        
        return response.json()
    
    except Exception as e:
        logger.error(f"Error fetching Google Fit steps: {str(e)}")
        return None

def fetch_heart_rate(integration, start_time, end_time):
    """Fetch heart rate data from Google Fit."""
    if not integration.is_connected():
        logger.error("Google Fit integration not connected")
        return None
    
    url = 'https://www.googleapis.com/fitness/v1/users/me/dataset:aggregate'
    headers = {
        'Authorization': f'Bearer {integration.access_token}',
        'Content-Type': 'application/json'
    }
    
    body = {
        "aggregateBy": [{
            "dataTypeName": "com.google.heart_rate.bpm",
        }],
        "bucketByTime": { "durationMillis": 3600000 },  # Hourly buckets
        "startTimeMillis": int(start_time.timestamp() * 1000),
        "endTimeMillis": int(end_time.timestamp() * 1000)
    }
    
    try:
        response = requests.post(url, headers=headers, json=body)
        if response.status_code != 200:
            logger.error(f"Google Fit heart rate fetch failed: {response.text}")
            return None
        
        return response.json()
    
    except Exception as e:
        logger.error(f"Error fetching Google Fit heart rate: {str(e)}")
        return None

def fetch_weight(integration, start_time, end_time):
    """Fetch weight data from Google Fit."""
    if not integration.is_connected():
        logger.error("Google Fit integration not connected")
        return None
    
    url = 'https://www.googleapis.com/fitness/v1/users/me/dataset:aggregate'
    headers = {
        'Authorization': f'Bearer {integration.access_token}',
        'Content-Type': 'application/json'
    }
    
    body = {
        "aggregateBy": [{
            "dataTypeName": "com.google.weight",
        }],
        "bucketByTime": { "durationMillis": 86400000 },  # Daily buckets
        "startTimeMillis": int(start_time.timestamp() * 1000),
        "endTimeMillis": int(end_time.timestamp() * 1000)
    }
    
    try:
        response = requests.post(url, headers=headers, json=body)
        if response.status_code != 200:
            logger.error(f"Google Fit weight fetch failed: {response.text}")
            return None
        
        return response.json()
    
    except Exception as e:
        logger.error(f"Error fetching Google Fit weight: {str(e)}")
        return None

def fetch_sleep(integration, start_time, end_time):
    """Fetch sleep data from Google Fit."""
    if not integration.is_connected():
        logger.error("Google Fit integration not connected")
        return None
    
    url = 'https://www.googleapis.com/fitness/v1/users/me/dataset:aggregate'
    headers = {
        'Authorization': f'Bearer {integration.access_token}',
        'Content-Type': 'application/json'
    }
    
    body = {
        "aggregateBy": [{
            "dataTypeName": "com.google.sleep.segment",
        }],
        "bucketByTime": { "durationMillis": 86400000 },  # Daily buckets
        "startTimeMillis": int(start_time.timestamp() * 1000),
        "endTimeMillis": int(end_time.timestamp() * 1000)
    }
    
    try:
        response = requests.post(url, headers=headers, json=body)
        if response.status_code != 200:
            logger.error(f"Google Fit sleep fetch failed: {response.text}")
            return None
        
        return response.json()
    
    except Exception as e:
        logger.error(f"Error fetching Google Fit sleep: {str(e)}")
        return None
