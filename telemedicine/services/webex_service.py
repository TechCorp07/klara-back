import json
import logging
import requests
from datetime import datetime, timedelta
from django.conf import settings
from django.utils import timezone

# Configure logging
logger = logging.getLogger(__name__)

class WebexException(Exception):
    """Exception for Cisco Webex API errors."""
    def __init__(self, message, status_code=None, response=None):
        self.message = message
        self.status_code = status_code
        self.response = response
        super().__init__(self.message)


def get_webex_token():
    """
    Use the configured API token for Webex.
    
    Returns:
        str: API token
    
    Raises:
        WebexException: If token is not configured
    """
    try:
        if not hasattr(settings, 'WEBEX_API_TOKEN') or not settings.WEBEX_API_TOKEN:
            raise WebexException("Webex API token is not configured")
        
        return settings.WEBEX_API_TOKEN
        
    except Exception as e:
        logger.error(f"Error getting Webex token: {str(e)}")
        raise WebexException(f"Error getting Webex token: {str(e)}")


def create_webex_meeting(topic, start_time, duration_minutes, host_email, attendee_emails=None):
    """
    Create a Cisco Webex meeting.
    
    Args:
        topic (str): Meeting title/name
        start_time (datetime): Meeting start time
        duration_minutes (int): Meeting duration in minutes
        host_email (str): Email of the meeting host
        attendee_emails (list, optional): List of attendee emails
    
    Returns:
        dict: Meeting details including join URL, meeting ID, etc.
    
    Raises:
        WebexException: If meeting creation fails
    """
    try:
        # Get token
        token = get_webex_token()
        
        # Calculate end time
        end_time = start_time + timedelta(minutes=duration_minutes)
        
        # Format times for Webex API (ISO 8601)
        start_iso = start_time.strftime("%Y-%m-%dT%H:%M:%S-00:00")
        end_iso = end_time.strftime("%Y-%m-%dT%H:%M:%S-00:00")
        
        # Prepare request
        api_url = "https://webexapis.com/v1/meetings"
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        # Prepare meeting data
        meeting_data = {
            "title": topic,
            "start": start_iso,
            "end": end_iso,
            "hostEmail": host_email,
            "enabledAutoRecordMeeting": False,
            "enabledJoinBeforeHost": False,
            "enableConnectAudioBeforeHost": False,
            "excludePassword": False,
            "publicMeeting": False,
            "enabledWebcastView": False,
            "sendEmail": True
        }
        
        # Add invitees if provided
        if attendee_emails:
            meeting_data["invitees"] = [{"email": email} for email in attendee_emails]
        
        # Make API call
        response = requests.post(
            api_url,
            headers=headers,
            data=json.dumps(meeting_data)
        )
        
        # Handle response
        if response.status_code == 200:
            result = response.json()
            
            # Extract password if available
            password = result.get('password', '')
            
            # Extract relevant information
            join_info = {
                'meeting_id': result.get('id'),
                'join_url': result.get('webLink'),
                'webex_meeting_number': result.get('meetingNumber'),
                'password': password,
                'status': 'created',
                'created_at': timezone.now().isoformat(),
                'platform': 'webex',
                'platform_data': {
                    'meeting_number': result.get('meetingNumber'),
                    'sip_address': result.get('sipAddress'),
                    'tele_conference': result.get('telephony', {})
                }
            }
            
            return join_info
        else:
            error_info = response.json() if response.content else {"message": "Unknown error"}
            logger.error(f"Webex meeting creation failed: {response.status_code} - {error_info}")
            raise WebexException(
                f"Failed to create Webex meeting: {error_info.get('message', 'Unknown error')}",
                status_code=response.status_code,
                response=error_info
            )
            
    except requests.RequestException as e:
        logger.error(f"Webex API request failed: {str(e)}")
        raise WebexException(f"Webex API request failed: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error creating Webex meeting: {str(e)}")
        raise WebexException(f"Unexpected error creating Webex meeting: {str(e)}")


def get_webex_meeting(meeting_id):
    """
    Get details of an existing Webex meeting.
    
    Args:
        meeting_id (str): Webex meeting ID
    
    Returns:
        dict: Meeting details
    
    Raises:
        WebexException: If retrieval fails
    """
    try:
        # Get token
        token = get_webex_token()
        
        # Prepare request
        api_url = f"https://webexapis.com/v1/meetings/{meeting_id}"
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
            logger.error(f"Failed to get Webex meeting: {response.status_code} - {error_info}")
            raise WebexException(
                f"Failed to get Webex meeting: {error_info.get('message', 'Unknown error')}",
                status_code=response.status_code,
                response=error_info
            )
            
    except requests.RequestException as e:
        logger.error(f"Webex API request failed: {str(e)}")
        raise WebexException(f"Webex API request failed: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error getting Webex meeting: {str(e)}")
        raise WebexException(f"Unexpected error getting Webex meeting: {str(e)}")


def update_webex_meeting(meeting_id, topic=None, start_time=None, duration_minutes=None, host_email=None):
    """
    Update an existing Webex meeting.
    
    Args:
        meeting_id (str): Webex meeting ID
        topic (str, optional): New meeting title. Defaults to None.
        start_time (datetime, optional): New start time. Defaults to None.
        duration_minutes (int, optional): New duration in minutes. Defaults to None.
        host_email (str, optional): New host email. Defaults to None.
    
    Returns:
        bool: True if successful
    
    Raises:
        WebexException: If update fails
    """
    try:
        # Get token
        token = get_webex_token()
        
        # Prepare request
        api_url = f"https://webexapis.com/v1/meetings/{meeting_id}"
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        # Prepare update data
        update_data = {}
        
        if topic:
            update_data['title'] = topic
            
        if start_time and duration_minutes:
            end_time = start_time + timedelta(minutes=duration_minutes)
            update_data['start'] = start_time.strftime("%Y-%m-%dT%H:%M:%S-00:00")
            update_data['end'] = end_time.strftime("%Y-%m-%dT%H:%M:%S-00:00")
            
        if host_email:
            update_data['hostEmail'] = host_email
        
        # Make API call (only if there's data to update)
        if update_data:
            response = requests.put(
                api_url,
                headers=headers,
                data=json.dumps(update_data)
            )
            
            # Handle response
            if response.status_code == 200:
                return True
            else:
                error_info = response.json() if response.content else {"message": "Unknown error"}
                logger.error(f"Failed to update Webex meeting: {response.status_code} - {error_info}")
                raise WebexException(
                    f"Failed to update Webex meeting: {error_info.get('message', 'Unknown error')}",
                    status_code=response.status_code,
                    response=error_info
                )
        
        return True
            
    except requests.RequestException as e:
        logger.error(f"Webex API request failed: {str(e)}")
        raise WebexException(f"Webex API request failed: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error updating Webex meeting: {str(e)}")
        raise WebexException(f"Unexpected error updating Webex meeting: {str(e)}")


def delete_webex_meeting(meeting_id):
    """
    Delete a scheduled Webex meeting.
    
    Args:
        meeting_id (str): Webex meeting ID
    
    Returns:
        bool: True if successful
    
    Raises:
        WebexException: If deletion fails
    """
    try:
        # Get token
        token = get_webex_token()
        
        # Prepare request
        api_url = f"https://webexapis.com/v1/meetings/{meeting_id}"
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        # Make API call
        response = requests.delete(api_url, headers=headers)
        
        # Handle response
        if response.status_code in [204, 200]:
            return True
        else:
            error_info = response.json() if response.content else {"message": "Unknown error"}
            logger.error(f"Failed to delete Webex meeting: {response.status_code} - {error_info}")
            raise WebexException(
                f"Failed to delete Webex meeting: {error_info.get('message', 'Unknown error')}",
                status_code=response.status_code,
                response=error_info
            )
            
    except requests.RequestException as e:
        logger.error(f"Webex API request failed: {str(e)}")
        raise WebexException(f"Webex API request failed: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error deleting Webex meeting: {str(e)}")
        raise WebexException(f"Unexpected error deleting Webex meeting: {str(e)}")
