import requests
import logging
from datetime import datetime, timedelta
from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)

def exchange_code(code):
    """Exchange authorization code for tokens."""
    token_url = 'https://wbsapi.withings.net/v2/oauth2'
    token_data = {
        'action': 'requesttoken',
        'client_id': settings.WITHINGS_CLIENT_ID,
        'client_secret': settings.WITHINGS_CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': settings.WITHINGS_CALLBACK_URL
    }
    
    try:
        response = requests.post(token_url, data=token_data)
        response_data = response.json()
        
        if response.status_code != 200 or response_data.get('status') != 0:
            logger.error(f"Withings token exchange failed: {response_data}")
            return None
        
        body = response_data.get('body', {})
        return {
            'access_token': body.get('access_token'),
            'refresh_token': body.get('refresh_token'),
            'expires_in': body.get('expires_in', 3600),
            'userid': body.get('userid')
        }
    
    except Exception as e:
        logger.error(f"Error exchanging Withings code: {str(e)}")
        return None

def refresh_token(integration):
    """Refresh Withings access token."""
    token_url = 'https://wbsapi.withings.net/v2/oauth2'
    token_data = {
        'action': 'requesttoken',
        'client_id': settings.WITHINGS_CLIENT_ID,
        'client_secret': settings.WITHINGS_CLIENT_SECRET,
        'grant_type': 'refresh_token',
        'refresh_token': integration.refresh_token
    }
    
    try:
        response = requests.post(token_url, data=token_data)
        response_data = response.json()
        
        if response.status_code != 200 or response_data.get('status') != 0:
            logger.error(f"Withings token refresh failed: {response_data}")
            return False
        
        body = response_data.get('body', {})
        
        # Update integration with new tokens
        integration.access_token = body.get('access_token')
        integration.refresh_token = body.get('refresh_token')
        integration.token_expiry = timezone.now() + timedelta(seconds=body.get('expires_in', 3600))
        integration.save(update_fields=['access_token', 'refresh_token', 'token_expiry'])
        
        return True
    
    except Exception as e:
        logger.error(f"Error refreshing Withings token: {str(e)}")
        return False

def fetch_measure(integration, action, params, startdate, enddate):
    """Fetch measurements from Withings API."""
    url = 'https://wbsapi.withings.net/measure'
    headers = {
        'Authorization': f'Bearer {integration.access_token}'
    }
    
    data = {
        'action': action,
        'startdate': startdate,
        'enddate': enddate,
        **params
    }
    
    try:
        response = requests.post(url, headers=headers, data=data)
        response_data = response.json()
        
        if response.status_code != 200 or response_data.get('status') != 0:
            logger.error(f"Withings API call failed: {response_data}")
            return None
        
        return response_data.get('body', {})
    
    except Exception as e:
        logger.error(f"Error fetching Withings measurements: {str(e)}")
        return None

def fetch_sleep(integration, startdate, enddate):
    """Fetch sleep data from Withings API."""
    url = 'https://wbsapi.withings.net/v2/sleep'
    headers = {
        'Authorization': f'Bearer {integration.access_token}'
    }
    
    data = {
        'action': 'getsummary',
        'startdateymd': datetime.fromtimestamp(startdate).strftime('%Y-%m-%d'),
        'enddateymd': datetime.fromtimestamp(enddate).strftime('%Y-%m-%d')
    }
    
    try:
        response = requests.post(url, headers=headers, data=data)
        response_data = response.json()
        
        if response.status_code != 200 or response_data.get('status') != 0:
            logger.error(f"Withings sleep API call failed: {response_data}")
            return None
        
        return response_data.get('body', {})
    
    except Exception as e:
        logger.error(f"Error fetching Withings sleep data: {str(e)}")
        return None

def fetch_activity(integration, startdate, enddate):
    """Fetch activity data from Withings API."""
    url = 'https://wbsapi.withings.net/v2/measure'
    headers = {
        'Authorization': f'Bearer {integration.access_token}'
    }
    
    data = {
        'action': 'getactivity',
        'startdateymd': datetime.fromtimestamp(startdate).strftime('%Y-%m-%d'),
        'enddateymd': datetime.fromtimestamp(enddate).strftime('%Y-%m-%d')
    }
    
    try:
        response = requests.post(url, headers=headers, data=data)
        response_data = response.json()
        
        if response.status_code != 200 or response_data.get('status') != 0:
            logger.error(f"Withings activity API call failed: {response_data}")
            return None
        
        return response_data.get('body', {})
    
    except Exception as e:
        logger.error(f"Error fetching Withings activity data: {str(e)}")
        return None

def get_default_date_range():
    """Get default date range for data fetching (last 30 days)."""
    end_date = timezone.now()
    start_date = end_date - timedelta(days=30)
    return start_date, end_date
