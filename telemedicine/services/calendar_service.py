# telemedicine/services/calendar_service.py
import logging
from datetime import datetime
from django.conf import settings
from django.core.mail import EmailMessage

logger = logging.getLogger(__name__)

class CalendarService:
    """Calendar integration service - extends existing notification system."""
    
    @staticmethod
    def send_calendar_invite(appointment, meeting_url, meeting_id):
        """Generate and send ICS calendar invites."""
        try:
            ics_content = CalendarService._generate_ics(appointment, meeting_url, meeting_id)
            
            # Send to patient
            CalendarService._send_ics_email(
                recipient_email=appointment.patient.email,
                recipient_name=appointment.patient.get_full_name(),
                ics_content=ics_content,
                appointment=appointment
            )
            
            # Send to provider
            CalendarService._send_ics_email(
                recipient_email=appointment.provider.email,
                recipient_name=appointment.provider.get_full_name(),
                ics_content=ics_content,
                appointment=appointment
            )
            
            return True
        except Exception as e:
            logger.error(f"Calendar invite failed: {str(e)}")
            return False
    
    @staticmethod
    def _generate_ics(appointment, meeting_url, meeting_id):
        """Generate ICS file content."""
        start_time = appointment.scheduled_time.strftime('%Y%m%dT%H%M%SZ')
        end_time = appointment.end_time.strftime('%Y%m%dT%H%M%SZ')
        uid = f"apt-{appointment.id}@klararety.com"
        
        return f"""BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Klararety//Healthcare//EN
METHOD:REQUEST
BEGIN:VEVENT
UID:{uid}
DTSTART:{start_time}
DTEND:{end_time}
SUMMARY:Medical Consultation - {appointment.patient.get_full_name()}
DESCRIPTION:Join Meeting: {meeting_url}\\nMeeting ID: {meeting_id}
LOCATION:{meeting_url}
STATUS:CONFIRMED
CLASS:CONFIDENTIAL
END:VEVENT
END:VCALENDAR"""
    
    @staticmethod
    def _send_ics_email(recipient_email, recipient_name, ics_content, appointment):
        """Send ICS file via email."""
        email = EmailMessage(
            subject=f"Calendar: Medical Consultation - {appointment.scheduled_time.strftime('%B %d, %Y')}",
            body=f"Dear {recipient_name},\n\nPlease find your calendar invitation attached.\n\nBest regards,\nKlararety Team",
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[recipient_email]
        )
        email.attach(f"appointment_{appointment.id}.ics", ics_content, 'text/calendar')
        email.send()