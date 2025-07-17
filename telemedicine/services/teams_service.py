import json
import logging
import requests
import uuid
from datetime import datetime, timedelta
from django.conf import settings
from django.utils import timezone
from msal import ConfidentialClientApplication

# Configure logging
logger = logging.getLogger(__name__)

class TeamsException(Exception):
    """Exception for Microsoft Teams API errors."""
    def __init__(self, message, status_code=None, response=None):
        self.message = message
        self.status_code = status_code
        self.response = response
        super().__init__(self.message)


def get_ms_graph_token():
    """
    Get Microsoft Graph API access token.
    
    Returns:
        str: Access token
    
    Raises:
        TeamsException: If token acquisition fails
    """
    try:
        # Configure Microsoft Authentication Library (MSAL) app
        app = ConfidentialClientApplication(
            settings.MS_TEAMS_CLIENT_ID,
            authority=f"https://login.microsoftonline.com/{settings.MS_TEAMS_TENANT_ID}",
            client_credential=settings.MS_TEAMS_CLIENT_SECRET
        )
        
        # Define scope for Microsoft Graph API
        scopes = ["https://graph.microsoft.com/.default"]
        
        # Acquire token for application
        result = app.acquire_token_for_client(scopes=scopes)
        
        if "access_token" in result:
            return result["access_token"]
        else:
            error_description = result.get("error_description", "Unknown error")
            logger.error(f"Failed to acquire MS Graph token: {error_description}")
            raise TeamsException(f"Failed to acquire MS Graph token: {error_description}")
        
    except Exception as e:
        logger.error(f"Error getting MS Graph token: {str(e)}")
        raise TeamsException(f"Error getting MS Graph token: {str(e)}")


def create_teams_meeting(topic, start_time, duration_minutes, organizer_email, attendee_emails=None):
    """
    Create a Microsoft Teams meeting.
    
    Args:
        topic (str): Meeting subject/name
        start_time (datetime): Meeting start time
        duration_minutes (int): Meeting duration in minutes
        organizer_email (str): Email of the meeting organizer
        attendee_emails (list, optional): List of attendee emails
    
    Returns:
        dict: Meeting details including join URL, meeting ID, etc.
    
    Raises:
        TeamsException: If meeting creation fails
    """
    try:
        # Get access token
        token = get_ms_graph_token()
        
        # Calculate end time
        end_time = start_time + timedelta(minutes=duration_minutes)
        
        # Format times for Graph API (ISO 8601)
        start_iso = start_time.isoformat()
        end_iso = end_time.isoformat()
        
        # Prepare attendees if provided
        attendees = []
        if attendee_emails:
            for email in attendee_emails:
                attendees.append({
                    "emailAddress": {
                        "address": email
                    },
                    "type": "required"
                })
        
        # Prepare request
        api_url = f"https://graph.microsoft.com/v1.0/users/{organizer_email}/onlineMeetings"
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        # Prepare meeting data
        meeting_data = {
            "subject": topic,
            "startDateTime": start_iso,
            "endDateTime": end_iso,
            "participants": {
                "organizer": {
                    "upn": organizer_email
                }
            },
            "lobbyBypassSettings": {
                "scope": "organization",
                "isDialInBypassEnabled": False
            }
        }
        
        # Add attendees if provided
        if attendees:
            meeting_data["attendees"] = attendees
        
        # Make API call
        response = requests.post(
            api_url,
            headers=headers,
            data=json.dumps(meeting_data)
        )
        
        # Handle response
        if response.status_code == 201:
            result = response.json()
            
            # Extract relevant information
            join_info = {
                'meeting_id': result.get('id'),
                'join_url': result.get('joinWebUrl'),
                'teams_meeting_id': result.get('id'),
                'status': 'created',
                'created_at': timezone.now().isoformat(),
                'platform': 'teams',
                'platform_data': {
                    'online_meeting_id': result.get('id'),
                    'join_info': result.get('joinInformation', {}),
                    'audio_conferencing': result.get('audioConferencing', {})
                }
            }
            
            return join_info
        else:
            error_info = response.json() if response.content else {"message": "Unknown error"}
            logger.error(f"Teams meeting creation failed: {response.status_code} - {error_info}")
            raise TeamsException(
                f"Failed to create Teams meeting: {error_info.get('message', 'Unknown error')}",
                status_code=response.status_code,
                response=error_info
            )
            
    except requests.RequestException as e:
        logger.error(f"Teams API request failed: {str(e)}")
        raise TeamsException(f"Teams API request failed: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error creating Teams meeting: {str(e)}")
        raise TeamsException(f"Unexpected error creating Teams meeting: {str(e)}")


def get_teams_meeting(meeting_id, organizer_email):
    """
    Get details of an existing Teams meeting.
    
    Args:
        meeting_id (str): Teams meeting ID
        organizer_email (str): Email of the meeting organizer
    
    Returns:
        dict: Meeting details
    
    Raises:
        TeamsException: If retrieval fails
    """
    try:
        # Get access token
        token = get_ms_graph_token()
        
        # Prepare request
        api_url = f"https://graph.microsoft.com/v1.0/users/{organizer_email}/onlineMeetings/{meeting_id}"
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
            logger.error(f"Failed to get Teams meeting: {response.status_code} - {error_info}")
            raise TeamsException(
                f"Failed to get Teams meeting: {error_info.get('message', 'Unknown error')}",
                status_code=response.status_code,
                response=error_info
            )
            
    except requests.RequestException as e:
        logger.error(f"Teams API request failed: {str(e)}")
        raise TeamsException(f"Teams API request failed: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error getting Teams meeting: {str(e)}")
        raise TeamsException(f"Unexpected error getting Teams meeting: {str(e)}")


def update_teams_meeting(meeting_id, organizer_email, topic=None, start_time=None, duration_minutes=None):
    """
    Update an existing Teams meeting.
    
    Args:
        meeting_id (str): Teams meeting ID
        organizer_email (str): Email of the meeting organizer
        topic (str, optional): New meeting subject. Defaults to None.
        start_time (datetime, optional): New start time. Defaults to None.
        duration_minutes (int, optional): New duration in minutes. Defaults to None.
    
    Returns:
        bool: True if successful
    
    Raises:
        TeamsException: If update fails
    """
    try:
        # Get access token
        token = get_ms_graph_token()
        
        # Prepare request
        api_url = f"https://graph.microsoft.com/v1.0/users/{organizer_email}/onlineMeetings/{meeting_id}"
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        # Prepare update data
        update_data = {}
        
        if topic:
            update_data['subject'] = topic
            
        if start_time and duration_minutes:
            end_time = start_time + timedelta(minutes=duration_minutes)
            update_data['startDateTime'] = start_time.isoformat()
            update_data['endDateTime'] = end_time.isoformat()
        
        # Make API call (only if there's data to update)
        if update_data:
            response = requests.patch(
                api_url,
                headers=headers,
                data=json.dumps(update_data)
            )
            
            # Handle response
            if response.status_code in [200, 204]:
                return True
            else:
                error_info = response.json() if response.content else {"message": "Unknown error"}
                logger.error(f"Failed to update Teams meeting: {response.status_code} - {error_info}")
                raise TeamsException(
                    f"Failed to update Teams meeting: {error_info.get('message', 'Unknown error')}",
                    status_code=response.status_code,
                    response=error_info
                )
        
        return True
            
    except requests.RequestException as e:
        logger.error(f"Teams API request failed: {str(e)}")
        raise TeamsException(f"Teams API request failed: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error updating Teams meeting: {str(e)}")
        raise TeamsException(f"Unexpected error updating Teams meeting: {str(e)}")


def delete_teams_meeting(meeting_id, organizer_email):
    """
    Delete a scheduled Teams meeting.
    
    Args:
        meeting_id (str): Teams meeting ID
        organizer_email (str): Email of the meeting organizer
    
    Returns:
        bool: True if successful
    
    Raises:
        TeamsException: If deletion fails
    """
    try:
        # Get access token
        token = get_ms_graph_token()
        
        # Prepare request
        api_url = f"https://graph.microsoft.com/v1.0/users/{organizer_email}/onlineMeetings/{meeting_id}"
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
            logger.error(f"Failed to delete Teams meeting: {response.status_code} - {error_info}")
            raise TeamsException(
                f"Failed to delete Teams meeting: {error_info.get('message', 'Unknown error')}",
                status_code=response.status_code,
                response=error_info
            )
            
    except requests.RequestException as e:
        logger.error(f"Teams API request failed: {str(e)}")
        raise TeamsException(f"Teams API request failed: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error deleting Teams meeting: {str(e)}")
        raise TeamsException(f"Unexpected error deleting Teams meeting: {str(e)}")
