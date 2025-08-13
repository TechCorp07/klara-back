import json
import time
import uuid
import logging
import requests
import base64
from datetime import datetime, timedelta
from django.conf import settings
from django.utils import timezone as django_timezone
from django.core.cache import cache
from rest_framework import status

# Configure logging
logger = logging.getLogger(__name__)

class ZoomMeetingException(Exception):
    """Exception for Zoom API errors."""
    def __init__(self, message, status_code=None, response=None):
        self.message = message
        self.status_code = status_code
        self.response = response
        super().__init__(self.message)


def get_zoom_access_token():
    """
    Get OAuth access token for Zoom API using Server-to-Server OAuth.
    
    Returns:
        str: Access token
    """
    try:
        # Check cache first
        token = cache.get('zoom_access_token')
        if token:
            return token
        
        # Prepare OAuth request
        client_id = settings.ZOOM_CLIENT_ID
        client_secret = settings.ZOOM_CLIENT_SECRET
        account_id = settings.ZOOM_ACCOUNT_ID
        
        if not all([client_id, client_secret, account_id]):
            raise ZoomMeetingException("Missing Zoom OAuth credentials in settings")
        
        # Create base64 encoded credentials
        auth_string = f"{client_id}:{client_secret}"
        auth_bytes = auth_string.encode('ascii')
        auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
        
        # Prepare token request
        headers = {
            'Authorization': f'Basic {auth_b64}',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        data = {
            'grant_type': 'account_credentials',
            'account_id': account_id
        }
        
        # Make token request
        response = requests.post(
            'https://zoom.us/oauth/token',
            headers=headers,
            data=data
        )
        
        # Handle response
        if response.status_code == 200:
            token_data = response.json()
            access_token = token_data['access_token']
            expires_in = token_data.get('expires_in', 3600)
            
            # Cache token (expires in 1 hour typically, cache for 55 minutes)
            cache.set('zoom_access_token', access_token, expires_in - 300)
            logger.info("Successfully obtained Zoom access token")
            return access_token
        else:
            error_info = response.json() if response.content else {"error": "Unknown error"}
            logger.error(f"Failed to get Zoom access token: {response.status_code} - {error_info}")
            raise ZoomMeetingException(
                f"Failed to get Zoom access token: {error_info.get('error_description', 'Unknown error')}",
                status_code=response.status_code,
                response=error_info
            )
            
    except requests.RequestException as e:
        logger.error(f"Zoom OAuth request failed: {str(e)}")
        raise ZoomMeetingException(f"Zoom OAuth request failed: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error getting Zoom access token: {str(e)}")
        raise ZoomMeetingException(f"Unexpected error getting Zoom access token: {str(e)}")


def create_zoom_meeting(topic, start_time, duration_minutes, meeting_timezone="UTC", settings_dict=None):
    """
    Create a Zoom meeting using OAuth authentication.
    
    Args:
        topic (str): Meeting topic/name
        start_time (datetime): Meeting start time
        duration_minutes (int): Meeting duration in minutes
        meeting_timezone (str, optional): Meeting timezone. Defaults to "UTC".
        settings_dict (dict, optional): Custom settings for the meeting. Defaults to None.
    
    Returns:
        dict: Meeting details including ID, join URL, password, etc.
    
    Raises:
        ZoomMeetingException: If meeting creation fails
    """
    try:
        # Get OAuth access token
        token = get_zoom_access_token()
        
        # Prepare request
        api_url = "https://api.zoom.us/v2/users/me/meetings"
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        # Format start time for Zoom API
        formatted_start_time = start_time.strftime('%Y-%m-%dT%H:%M:%S')
        
        # Default meeting settings for healthcare
        default_settings = {
            'host_video': True,
            'participant_video': True,
            'join_before_host': False,
            'mute_upon_entry': True,
            'waiting_room': True,
            'audio': 'both',
            'auto_recording': 'none',
            'meeting_authentication': False,
            'approval_type': 0,  # Automatically approve
            'enforce_login': False,
            'alternative_hosts': '',
            'use_pmi': False
        }
        
        # Override with custom settings if provided
        if settings_dict:
            default_settings.update(settings_dict)
        
        # Prepare meeting data
        meeting_data = {
            'topic': topic,
            'type': 2,  # Scheduled meeting
            'start_time': formatted_start_time,
            'duration': duration_minutes,
            'timezone': meeting_timezone,
            'agenda': f"Medical consultation scheduled for {formatted_start_time}",
            'settings': default_settings
        }
        
        # Make API call
        response = requests.post(
            api_url,
            headers=headers,
            data=json.dumps(meeting_data)
        )
        
        # Handle response
        if response.status_code == 201:
            result = response.json()
            logger.info(f"Successfully created Zoom meeting: {result.get('id')}")
            return {
                'meeting_id': str(result.get('id')),
                'join_url': result.get('join_url'),
                'password': result.get('password', ''),
                'host_url': result.get('start_url', ''),
                'host_key': '',  # Host key is not returned by the API
                'status': 'created',
                'created_at': django_timezone.now().isoformat(),
                'settings': result.get('settings', {}),
                'platform_data': result  # Store full response
            }
        else:
            error_info = response.json() if response.content else {"message": "Unknown error"}
            logger.error(f"Zoom meeting creation failed: {response.status_code} - {error_info}")
            raise ZoomMeetingException(
                f"Failed to create Zoom meeting: {error_info.get('message', 'Unknown error')}",
                status_code=response.status_code,
                response=error_info
            )
            
    except requests.RequestException as e:
        logger.error(f"Zoom API request failed: {str(e)}")
        raise ZoomMeetingException(f"Zoom API request failed: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error creating Zoom meeting: {str(e)}")
        raise ZoomMeetingException(f"Unexpected error creating Zoom meeting: {str(e)}")


def get_zoom_meeting(meeting_id):
    """
    Get details of an existing Zoom meeting.
    
    Args:
        meeting_id (str): Zoom meeting ID
    
    Returns:
        dict: Meeting details
    
    Raises:
        ZoomMeetingException: If retrieval fails
    """
    try:
        # Get OAuth access token
        token = get_zoom_access_token()
        
        # Prepare request
        api_url = f"https://api.zoom.us/v2/meetings/{meeting_id}"
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        # Make API call
        response = requests.get(api_url, headers=headers)
        
        # Handle response
        if response.status_code == 200:
            return response.json()
        else:
            error_info = response.json() if response.content else {"message": "Unknown error"}
            logger.error(f"Failed to get Zoom meeting: {response.status_code} - {error_info}")
            raise ZoomMeetingException(
                f"Failed to get Zoom meeting: {error_info.get('message', 'Unknown error')}",
                status_code=response.status_code,
                response=error_info
            )
            
    except requests.RequestException as e:
        logger.error(f"Zoom API request failed: {str(e)}")
        raise ZoomMeetingException(f"Zoom API request failed: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error getting Zoom meeting: {str(e)}")
        raise ZoomMeetingException(f"Unexpected error getting Zoom meeting: {str(e)}")


def update_zoom_meeting(meeting_id, topic=None, start_time=None, duration=None, settings_dict=None):
    """
    Update an existing Zoom meeting.
    
    Args:
        meeting_id (str): Zoom meeting ID
        topic (str, optional): New meeting topic. Defaults to None.
        start_time (datetime, optional): New start time. Defaults to None.
        duration (int, optional): New duration in minutes. Defaults to None.
        settings_dict (dict, optional): Updated settings. Defaults to None.
    
    Returns:
        bool: True if successful
    
    Raises:
        ZoomMeetingException: If update fails
    """
    try:
        # Get OAuth access token
        token = get_zoom_access_token()
        
        # Prepare request
        api_url = f"https://api.zoom.us/v2/meetings/{meeting_id}"
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        # Prepare update data
        update_data = {}
        
        if topic:
            update_data['topic'] = topic
            
        if start_time:
            update_data['start_time'] = start_time.strftime('%Y-%m-%dT%H:%M:%S')
            
        if duration:
            update_data['duration'] = duration
            
        if settings_dict:
            update_data['settings'] = settings_dict
        
        # Make API call (only if there's data to update)
        if update_data:
            response = requests.patch(
                api_url,
                headers=headers,
                data=json.dumps(update_data)
            )
            
            # Handle response
            if response.status_code == 204:
                logger.info(f"Successfully updated Zoom meeting: {meeting_id}")
                return True
            else:
                error_info = response.json() if response.content else {"message": "Unknown error"}
                logger.error(f"Failed to update Zoom meeting: {response.status_code} - {error_info}")
                raise ZoomMeetingException(
                    f"Failed to update Zoom meeting: {error_info.get('message', 'Unknown error')}",
                    status_code=response.status_code,
                    response=error_info
                )
        
        return True
            
    except requests.RequestException as e:
        logger.error(f"Zoom API request failed: {str(e)}")
        raise ZoomMeetingException(f"Zoom API request failed: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error updating Zoom meeting: {str(e)}")
        raise ZoomMeetingException(f"Unexpected error updating Zoom meeting: {str(e)}")


def delete_zoom_meeting(meeting_id, cancel_meeting_reminder=True):
    """
    Delete a scheduled Zoom meeting.
    
    Args:
        meeting_id (str): Zoom meeting ID
        cancel_meeting_reminder (bool, optional): Whether to send cancellation emails. Defaults to True.
    
    Returns:
        bool: True if successful
    
    Raises:
        ZoomMeetingException: If deletion fails
    """
    try:
        # Get OAuth access token
        token = get_zoom_access_token()
        
        # Prepare request
        api_url = f"https://api.zoom.us/v2/meetings/{meeting_id}"
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        # Add query parameters
        params = {'cancel_meeting_reminder': str(cancel_meeting_reminder).lower()}
        
        # Make API call
        response = requests.delete(api_url, headers=headers, params=params)
        
        # Handle response
        if response.status_code in [204, 200]:
            logger.info(f"Successfully deleted Zoom meeting: {meeting_id}")
            return True
        else:
            error_info = response.json() if response.content else {"message": "Unknown error"}
            logger.error(f"Failed to delete Zoom meeting: {response.status_code} - {error_info}")
            raise ZoomMeetingException(
                f"Failed to delete Zoom meeting: {error_info.get('message', 'Unknown error')}",
                status_code=response.status_code,
                response=error_info
            )
            
    except requests.RequestException as e:
        logger.error(f"Zoom API request failed: {str(e)}")
        raise ZoomMeetingException(f"Zoom API request failed: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error deleting Zoom meeting: {str(e)}")
        raise ZoomMeetingException(f"Unexpected error deleting Zoom meeting: {str(e)}")


def get_meeting_recordings(meeting_id):
    """
    Get recordings for a specific meeting.
    
    Args:
        meeting_id (str): Zoom meeting ID
    
    Returns:
        dict: Recording information
    
    Raises:
        ZoomMeetingException: If retrieval fails
    """
    try:
        # Get OAuth access token
        token = get_zoom_access_token()
        
        # Prepare request
        api_url = f"https://api.zoom.us/v2/meetings/{meeting_id}/recordings"
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        # Make API call
        response = requests.get(api_url, headers=headers)
        
        # Handle response
        if response.status_code == 200:
            return response.json()
        else:
            error_info = response.json() if response.content else {"message": "Unknown error"}
            logger.error(f"Failed to get meeting recordings: {response.status_code} - {error_info}")
            raise ZoomMeetingException(
                f"Failed to get meeting recordings: {error_info.get('message', 'Unknown error')}",
                status_code=response.status_code,
                response=error_info
            )
            
    except requests.RequestException as e:
        logger.error(f"Zoom API request failed: {str(e)}")
        raise ZoomMeetingException(f"Zoom API request failed: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error getting meeting recordings: {str(e)}")
        raise ZoomMeetingException(f"Unexpected error getting meeting recordings: {str(e)}")


def test_zoom_connection():
    """
    Test Zoom API connection.
    
    Returns:
        dict: Connection test results
    """
    try:
        # Get OAuth access token
        token = get_zoom_access_token()
        
        # Test API call
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        response = requests.get('https://api.zoom.us/v2/users/me', headers=headers)
        
        if response.status_code == 200:
            user_info = response.json()
            return {
                'status': 'success',
                'message': 'Zoom API connection successful',
                'zoom_user': user_info.get('email', 'Unknown'),
                'account_type': user_info.get('type', 'Unknown'),
                'account_id': user_info.get('account_id', 'Unknown')
            }
        else:
            return {
                'status': 'error',
                'message': f'Zoom API error: {response.status_code}',
                'details': response.json() if response.content else None
            }
            
    except Exception as e:
        return {
            'status': 'error',
            'message': f'Zoom connection test failed: {str(e)}'
        }
