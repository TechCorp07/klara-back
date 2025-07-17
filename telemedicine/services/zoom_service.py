import jwt
import json
import time
import uuid
import logging
import requests
from datetime import datetime, timedelta
from django.conf import settings
from django.utils import timezone
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


def generate_zoom_jwt():
    """
    Generate JWT token for Zoom API authentication.
    
    Returns:
        str: JWT token
    """
    try:
        iat = int(time.time())
        exp = iat + 3600  # Token expires in 1 hour
        
        payload = {
            'iss': settings.ZOOM_API_KEY,
            'exp': exp,
            'iat': iat
        }
        
        token = jwt.encode(payload, settings.ZOOM_API_SECRET, algorithm='HS256')
        
        # If token is returned as bytes, decode to string
        if isinstance(token, bytes):
            return token.decode('utf-8')
        return token
        
    except Exception as e:
        logger.error(f"Error generating Zoom JWT: {str(e)}")
        raise ZoomMeetingException(f"Failed to generate Zoom authentication token: {str(e)}")


def create_zoom_meeting(topic, start_time, duration_minutes, timezone="UTC", settings_dict=None):
    """
    Create a Zoom meeting.
    
    Args:
        topic (str): Meeting topic/name
        start_time (datetime): Meeting start time
        duration_minutes (int): Meeting duration in minutes
        timezone (str, optional): Timezone. Defaults to "UTC".
        settings_dict (dict, optional): Custom settings for the meeting. Defaults to None.
    
    Returns:
        dict: Meeting details including ID, join URL, password, etc.
    
    Raises:
        ZoomMeetingException: If meeting creation fails
    """
    try:
        # Generate JWT token
        token = generate_zoom_jwt()
        
        # Prepare request
        api_url = "https://api.zoom.us/v2/users/me/meetings"
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        # Format start time for Zoom API
        formatted_start_time = start_time.strftime('%Y-%m-%dT%H:%M:%S')
        
        # Default meeting settings
        default_settings = {
            'host_video': True,
            'participant_video': True,
            'join_before_host': False,
            'mute_upon_entry': True,
            'waiting_room': True,
            'audio': 'both',
            'auto_recording': 'none',
            'meeting_authentication': False
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
            'timezone': timezone,
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
            return {
                'meeting_id': result.get('id'),
                'join_url': result.get('join_url'),
                'password': result.get('password', ''),
                'host_url': result.get('start_url', ''),
                'status': 'created',
                'created_at': timezone.now().isoformat(),
                'settings': result.get('settings', {})
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
        # Generate JWT token
        token = generate_zoom_jwt()
        
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
        # Generate JWT token
        token = generate_zoom_jwt()
        
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
        # Generate JWT token
        token = generate_zoom_jwt()
        
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
        # Generate JWT token
        token = generate_zoom_jwt()
        
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


def generate_signature(api_key, api_secret, meeting_number, role):
    """
    Generate a signature for joining a Zoom meeting via client SDK.
    
    Args:
        api_key (str): Zoom API Key
        api_secret (str): Zoom API Secret
        meeting_number (str): Zoom meeting ID
        role (int): Role (0 for attendee, 1 for host)
    
    Returns:
        str: Signature for client SDK
    """
    try:
        iat = int(time.time())
        exp = iat + 60 * 60 * 2  # Token expires in 2 hours
        
        payload = {
            'iss': api_key,
            'exp': exp,
            'iat': iat,
            'mn': meeting_number,
            'role': role
        }
        
        token = jwt.encode(payload, api_secret, algorithm='HS256')
        
        # If token is returned as bytes, decode to string
        if isinstance(token, bytes):
            return token.decode('utf-8')
        return token
        
    except Exception as e:
        logger.error(f"Error generating Zoom signature: {str(e)}")
        raise ZoomMeetingException(f"Failed to generate Zoom signature: {str(e)}")
