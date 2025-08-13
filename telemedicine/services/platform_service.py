import logging
from django.utils import timezone
from . import zoom_service, teams_service, webex_service
from telemedicine.models import Consultation

# Configure logging
logger = logging.getLogger(__name__)

class VideoServiceException(Exception):
    """Exception for video service errors."""
    pass


def create_meeting(consultation, platform, organizer_email, patient_email=None):
    """
    Create a meeting using the specified video platform.
    
    Args:
        consultation (Consultation): Consultation object
        platform (str): Video platform to use (zoom, teams, webex)
        organizer_email (str): Email of the meeting organizer
        patient_email (str, optional): Email of the patient
    
    Returns:
        dict: Meeting details including join URL, meeting ID, etc.
    
    Raises:
        VideoServiceException: If meeting creation fails
    """
    try:
        # Get appointment details for meeting topic and timing
        if not consultation.appointment:
            raise VideoServiceException("Consultation has no associated appointment")
            
        appointment = consultation.appointment
        patient_name = appointment.patient.get_full_name()
        provider_name = f"Dr. {appointment.provider.last_name}"
        
        # Set meeting topic
        topic = f"Medical Consultation - {patient_name} with {provider_name}"
        
        # Calculate meeting duration
        now = timezone.now()
        end_time = appointment.end_time
        if end_time < now:
            end_time = now + timezone.timedelta(minutes=30)
        
        duration_minutes = max(15, int((end_time - now).total_seconds() / 60))
        
        # Create attendees list if patient email is provided
        attendee_emails = [patient_email] if patient_email else None
        
        # Create meeting based on platform
        if platform == Consultation.Platform.ZOOM:
            # Create Zoom meeting
            meeting_data = zoom_service.create_zoom_meeting(
                topic=topic,
                start_time=now,
                duration_minutes=duration_minutes,
                meeting_timezone=appointment.timezone or "UTC",
                settings_dict={
                    'host_video': True,
                    'participant_video': True,
                    'join_before_host': False,
                    'mute_upon_entry': True,
                    'waiting_room': True,
                    'audio': 'both',
                    'auto_recording': 'none' if not consultation.recording_enabled else 'cloud'
                }
            )
            
            return meeting_data
            
        elif platform == Consultation.Platform.TEAMS:
            # Create Microsoft Teams meeting
            meeting_data = teams_service.create_teams_meeting(
                topic=topic,
                start_time=now,
                duration_minutes=duration_minutes,
                organizer_email=organizer_email,
                attendee_emails=attendee_emails
            )
            
            return meeting_data
            
        elif platform == Consultation.Platform.WEBEX:
            # Create Cisco Webex meeting
            meeting_data = webex_service.create_webex_meeting(
                topic=topic,
                start_time=now,
                duration_minutes=duration_minutes,
                host_email=organizer_email,
                attendee_emails=attendee_emails
            )
            
            return meeting_data
            
        else:
            raise VideoServiceException(f"Unsupported platform: {platform}")
            
    except zoom_service.ZoomMeetingException as e:
        logger.error(f"Zoom meeting creation failed: {str(e)}")
        raise VideoServiceException(f"Zoom meeting creation failed: {str(e)}")
    except teams_service.TeamsException as e:
        logger.error(f"Teams meeting creation failed: {str(e)}")
        raise VideoServiceException(f"Teams meeting creation failed: {str(e)}")
    except webex_service.WebexException as e:
        logger.error(f"Webex meeting creation failed: {str(e)}")
        raise VideoServiceException(f"Webex meeting creation failed: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error creating meeting: {str(e)}")
        raise VideoServiceException(f"Unexpected error creating meeting: {str(e)}")


def update_meeting(consultation, topic=None, start_time=None, duration_minutes=None, recording_enabled=None):
    """
    Update a meeting using the consultation's platform.
    
    Args:
        consultation (Consultation): Consultation object
        topic (str, optional): New meeting topic
        start_time (datetime, optional): New start time
        duration_minutes (int, optional): New duration in minutes
        recording_enabled (bool, optional): Enable/disable recording
    
    Returns:
        bool: True if successful
    
    Raises:
        VideoServiceException: If update fails
    """
    try:
        # Check if consultation has meeting details
        if not consultation.meeting_id:
            raise VideoServiceException("Consultation has no meeting ID")
            
        # Get organizer email
        organizer_email = consultation.appointment.provider.email if consultation.appointment else None
        
        # Update meeting based on platform
        if consultation.platform == Consultation.Platform.ZOOM:
            # Prepare settings update if recording changed
            settings_dict = None
            if recording_enabled is not None:
                settings_dict = {
                    'auto_recording': 'cloud' if recording_enabled else 'none'
                }
                
            # Update Zoom meeting
            return zoom_service.update_zoom_meeting(
                meeting_id=consultation.meeting_id,
                topic=topic,
                start_time=start_time,
                duration=duration_minutes,
                settings_dict=settings_dict
            )
            
        elif consultation.platform == Consultation.Platform.TEAMS:
            # Update Microsoft Teams meeting
            if not organizer_email:
                raise VideoServiceException("Provider email is required for Teams meeting update")
                
            return teams_service.update_teams_meeting(
                meeting_id=consultation.meeting_id,
                organizer_email=organizer_email,
                topic=topic,
                start_time=start_time,
                duration_minutes=duration_minutes
            )
            
        elif consultation.platform == Consultation.Platform.WEBEX:
            # Update Cisco Webex meeting
            return webex_service.update_webex_meeting(
                meeting_id=consultation.meeting_id,
                topic=topic,
                start_time=start_time,
                duration_minutes=duration_minutes,
                host_email=organizer_email
            )
            
        else:
            raise VideoServiceException(f"Unsupported platform: {consultation.platform}")
            
    except zoom_service.ZoomMeetingException as e:
        logger.error(f"Zoom meeting update failed: {str(e)}")
        raise VideoServiceException(f"Zoom meeting update failed: {str(e)}")
    except teams_service.TeamsException as e:
        logger.error(f"Teams meeting update failed: {str(e)}")
        raise VideoServiceException(f"Teams meeting update failed: {str(e)}")
    except webex_service.WebexException as e:
        logger.error(f"Webex meeting update failed: {str(e)}")
        raise VideoServiceException(f"Webex meeting update failed: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error updating meeting: {str(e)}")
        raise VideoServiceException(f"Unexpected error updating meeting: {str(e)}")


def delete_meeting(consultation):
    """
    Delete a meeting using the consultation's platform.
    
    Args:
        consultation (Consultation): Consultation object
    
    Returns:
        bool: True if successful
    
    Raises:
        VideoServiceException: If deletion fails
    """
    try:
        # Check if consultation has meeting details
        if not consultation.meeting_id:
            logger.warning("No meeting ID found for consultation")
            return True  # Nothing to delete
            
        # Get organizer email
        organizer_email = consultation.appointment.provider.email if consultation.appointment else None
        
        # Delete meeting based on platform
        if consultation.platform == Consultation.Platform.ZOOM:
            # Delete Zoom meeting
            return zoom_service.delete_zoom_meeting(
                meeting_id=consultation.meeting_id,
                cancel_meeting_reminder=True
            )
            
        elif consultation.platform == Consultation.Platform.TEAMS:
            # Delete Microsoft Teams meeting
            if not organizer_email:
                raise VideoServiceException("Provider email is required for Teams meeting deletion")
                
            return teams_service.delete_teams_meeting(
                meeting_id=consultation.meeting_id,
                organizer_email=organizer_email
            )
            
        elif consultation.platform == Consultation.Platform.WEBEX:
            # Delete Cisco Webex meeting
            return webex_service.delete_webex_meeting(
                meeting_id=consultation.meeting_id
            )
            
        else:
            raise VideoServiceException(f"Unsupported platform: {consultation.platform}")
            
    except zoom_service.ZoomMeetingException as e:
        logger.error(f"Zoom meeting deletion failed: {str(e)}")
        raise VideoServiceException(f"Zoom meeting deletion failed: {str(e)}")
    except teams_service.TeamsException as e:
        logger.error(f"Teams meeting deletion failed: {str(e)}")
        raise VideoServiceException(f"Teams meeting deletion failed: {str(e)}")
    except webex_service.WebexException as e:
        logger.error(f"Webex meeting deletion failed: {str(e)}")
        raise VideoServiceException(f"Webex meeting deletion failed: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error deleting meeting: {str(e)}")
        raise VideoServiceException(f"Unexpected error deleting meeting: {str(e)}")


def get_join_info(consultation):
    """
    Get formatted join information for a consultation.
    
    Args:
        consultation (Consultation): Consultation object
    
    Returns:
        dict: Formatted join information
    
    Raises:
        VideoServiceException: If retrieval fails
    """
    try:
        # Check if consultation has meeting details
        if not consultation.meeting_id or not consultation.join_url:
            raise VideoServiceException("Consultation has no meeting details")
            
        # Basic join info that works across platforms
        join_info = {
            'meeting_id': consultation.meeting_id,
            'join_url': consultation.join_url,
            'password': consultation.password,
            'platform': consultation.platform,
            'platform_display': consultation.get_platform_display()
        }
        
        # Add platform-specific details if needed
        if consultation.platform_data:
            # Get platform data as dict
            platform_data = consultation.platform_data
            
            if consultation.platform == Consultation.Platform.ZOOM:
                # Add Zoom-specific details if available
                join_info['host_url'] = platform_data.get('host_url', '')
                
            elif consultation.platform == Consultation.Platform.TEAMS:
                # Add Teams-specific details if available
                join_info['audio_info'] = platform_data.get('audio_conferencing', {})
                
            elif consultation.platform == Consultation.Platform.WEBEX:
                # Add Webex-specific details if available
                join_info['sip_address'] = platform_data.get('sip_address', '')
                join_info['teleconference'] = platform_data.get('tele_conference', {})
        
        return join_info
            
    except Exception as e:
        logger.error(f"Error getting join information: {str(e)}")
        raise VideoServiceException(f"Error getting join information: {str(e)}")
