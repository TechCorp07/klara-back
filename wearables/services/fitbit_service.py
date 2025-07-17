import requests
import logging
from datetime import datetime, timedelta
from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)

def exchange_code(code):
    """Exchange authorization code for tokens."""
    # Check if settings are configured
    if not hasattr(settings, 'FITBIT_CLIENT_ID') or not settings.FITBIT_CLIENT_ID:
        logger.error("Fitbit API credentials not configured")
        return None
        
    token_url = 'https://api.fitbit.com/oauth2/token'
    token_data = {
        'client_id': settings.FITBIT_CLIENT_ID,
        'client_secret': settings.FITBIT_CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': f"{settings.BASE_URL}/api/wearables/callback/fitbit/"
    }
    
    try:
        response = requests.post(token_url, data=token_data)
        response_data = response.json()
        
        if response.status_code != 200:
            logger.error(f"Fitbit token exchange failed: {response_data}")
            return None
        
        return {
            'access_token': response_data.get('access_token'),
            'refresh_token': response_data.get('refresh_token'),
            'expires_in': response_data.get('expires_in', 3600),
            'user_id': response_data.get('user_id'),
            'scope': response_data.get('scope')
        }
    
    except Exception as e:
        logger.error(f"Error exchanging Fitbit code: {str(e)}")
        return None

def refresh_token(integration):
    """Refresh Fitbit access token."""
    # Check if settings are configured
    if not hasattr(settings, 'FITBIT_CLIENT_ID') or not settings.FITBIT_CLIENT_ID:
        logger.error("Fitbit API credentials not configured")
        return False
    
    token_url = 'https://api.fitbit.com/oauth2/token'
    headers = {
        'Authorization': f'Basic {settings.FITBIT_BASIC_AUTH}',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    data = {
        'grant_type': 'refresh_token',
        'refresh_token': integration.refresh_token
    }
    
    try:
        response = requests.post(token_url, headers=headers, data=data)
        response_data = response.json()
        
        if response.status_code != 200:
            logger.error(f"Fitbit token refresh failed: {response_data}")
            return False
        
        # Update integration with new tokens
        integration.access_token = response_data.get('access_token')
        integration.refresh_token = response_data.get('refresh_token')
        integration.token_expiry = timezone.now() + timedelta(seconds=response_data.get('expires_in', 3600))
        integration.save(update_fields=['access_token', 'refresh_token', 'token_expiry'])
        
        return True
    
    except Exception as e:
        logger.error(f"Error refreshing Fitbit token: {str(e)}")
        return False

def fetch_profile(integration):
    """Fetch user profile from Fitbit."""
    if not integration.is_connected():
        logger.error("Fitbit integration not connected")
        return None
    
    url = 'https://api.fitbit.com/1/user/-/profile.json'
    headers = {
        'Authorization': f'Bearer {integration.access_token}'
    }
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            logger.error(f"Fitbit profile fetch failed: {response.text}")
            return None
        
        return response.json().get('user', {})
    
    except Exception as e:
        logger.error(f"Error fetching Fitbit profile: {str(e)}")
        return None

def fetch_activities(integration, date):
    """Fetch activity data for a specific date."""
    if not integration.is_connected():
        logger.error("Fitbit integration not connected")
        return None
    
    date_str = date.strftime('%Y-%m-%d')
    url = f'https://api.fitbit.com/1/user/-/activities/date/{date_str}.json'
    headers = {
        'Authorization': f'Bearer {integration.access_token}'
    }
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            logger.error(f"Fitbit activities fetch failed: {response.text}")
            return None
        
        return response.json()
    
    except Exception as e:
        logger.error(f"Error fetching Fitbit activities: {str(e)}")
        return None

def fetch_heart_rate(integration, date):
    """Fetch heart rate data for a specific date."""
    if not integration.is_connected():
        logger.error("Fitbit integration not connected")
        return None
    
    date_str = date.strftime('%Y-%m-%d')
    url = f'https://api.fitbit.com/1/user/-/activities/heart/date/{date_str}/1d.json'
    headers = {
        'Authorization': f'Bearer {integration.access_token}'
    }
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            logger.error(f"Fitbit heart rate fetch failed: {response.text}")
            return None
        
        return response.json()
    
    except Exception as e:
        logger.error(f"Error fetching Fitbit heart rate: {str(e)}")
        return None

def fetch_sleep(integration, date):
    """Fetch sleep data for a specific date."""
    if not integration.is_connected():
        logger.error("Fitbit integration not connected")
        return None
    
    date_str = date.strftime('%Y-%m-%d')
    url = f'https://api.fitbit.com/1.2/user/-/sleep/date/{date_str}.json'
    headers = {
        'Authorization': f'Bearer {integration.access_token}'
    }
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            logger.error(f"Fitbit sleep fetch failed: {response.text}")
            return None
        
        return response.json()
    
    except Exception as e:
        logger.error(f"Error fetching Fitbit sleep: {str(e)}")
        return None

def fetch_weight(integration, date):
    """Fetch weight data for a specific date."""
    if not integration.is_connected():
        logger.error("Fitbit integration not connected")
        return None
    
    date_str = date.strftime('%Y-%m-%d')
    url = f'https://api.fitbit.com/1/user/-/body/log/weight/date/{date_str}.json'
    headers = {
        'Authorization': f'Bearer {integration.access_token}'
    }
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            logger.error(f"Fitbit weight fetch failed: {response.text}")
            return None
        
        return response.json()
    
    except Exception as e:
        logger.error(f"Error fetching Fitbit weight: {str(e)}")
        return None
