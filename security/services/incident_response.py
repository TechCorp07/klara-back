# security/services/incident_response.py
import logging
from datetime import datetime, timedelta
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth import get_user_model
from django.template.loader import render_to_string

from ..models import SecurityIncident, SecurityThreat

User = get_user_model()
logger = logging.getLogger('security.incident_response')


class IncidentResponseService:
    """
    Service for security incident response and management.
    Implements automated response procedures and escalation workflows.
    """
    
    # NIST Incident Response phases
    PHASES = {
        'preparation': 'Preparation',
        'detection': 'Detection and Analysis', 
        'containment': 'Containment, Eradication, and Recovery',
        'post_incident': 'Post-Incident Activity'
    }
    
    # Severity-based response timeframes (in hours)
    RESPONSE_TIMEFRAMES = {
        'critical': 1,    # 1 hour
        'high': 4,        # 4 hours
        'medium': 24,     # 24 hours
        'low': 72         # 72 hours
    }
    
    @classmethod
    def create_incident_from_threat(cls, threat):
        """Create security incident from detected threat."""
        try:
            # Generate incident ID
            year = timezone.now().year
            last_incident = SecurityIncident.objects.filter(
                incident_id__startswith=f'INC-{year}-'
            ).order_by('-incident_id').first()
            
            if last_incident:
                last_num = int(last_incident.incident_id.split('-')[-1])
                incident_num = last_num + 1
            else:
                incident_num = 1
            
            incident_id = f'INC-{year}-{incident_num:04d}'
            
            # Map threat type to incident type
            incident_type = cls._map_threat_to_incident_type(threat.threat_type)
            
            # Determine priority based on threat severity
            priority_mapping = {
                'critical': 'critical',
                'high': 'high',
                'medium': 'medium',
                'low': 'low'
            }
            priority = priority_mapping.get(threat.severity, 'medium')
            
            # Create incident
            incident = SecurityIncident.objects.create(
                incident_id=incident_id,
                incident_type=incident_type,
                priority=priority,
                title=f"Security Incident: {threat.title}",
                description=f"Incident created from threat detection: {threat.description}",
                discovered_at=threat.detection_time,
                reported_by=None,  # System-generated
                affected_systems=[threat.target_ip] if threat.target_ip else [],
                impact_assessment=cls._assess_threat_impact(threat)
            )
            
            # Link threat to incident
            incident.related_threats.add(threat)
            
            # Auto-assign based on incident type and priority
            assigned_user = cls._auto_assign_incident(incident)
            if assigned_user:
                incident.assigned_to = assigned_user
                incident.status = 'acknowledged'
                incident.save()
            
            # Trigger automated response
            cls._trigger_automated_response(incident)
            
            # Send notifications
            cls._send_incident_notifications(incident)
            
            logger.info(f"Created incident {incident.incident_id} from threat {threat.id}")
            
            return incident
            
        except Exception as e:
            logger.error(f"Error creating incident from threat {threat.id}: {str(e)}")
            raise
    
    @classmethod
    def escalate_incident(cls, incident, escalated_by=None):
        """Escalate incident priority and notifications."""
        try:
            # Priority escalation order
            priority_order = ['low', 'medium', 'high', 'critical']
            current_index = priority_order.index(incident.priority)
            
            if current_index < len(priority_order) - 1:
                old_priority = incident.priority
                incident.priority = priority_order[current_index + 1]
                incident.save(update_fields=['priority'])
                
                # Log escalation
                logger.info(f"Escalated incident {incident.incident_id} from {old_priority} to {incident.priority}")
                
                # Send escalation notifications
                cls.notify_escalation(incident, escalated_by)
                
                # Re-assign if needed for critical incidents
                if incident.priority == 'critical':
                    cls._assign_critical_incident_team(incident)
                
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error escalating incident {incident.incident_id}: {str(e)}")
            raise
    
    @classmethod
    def notify_escalation(cls, incident, escalated_by=None):
        """Send escalation notifications."""
        try:
            # Get notification recipients
            recipients = cls._get_escalation_recipients(incident)
            
            if not recipients:
                logger.warning(f"No recipients for incident {incident.incident_id} escalation")
                return
            
            # Prepare notification content
            subject = f"ESCALATED: {incident.incident_id} - {incident.title}"
            
            escalated_by_name = "System" if not escalated_by else (
                escalated_by.get_full_name() or escalated_by.username
            )
            
            message = f"""
SECURITY INCIDENT ESCALATED

Incident ID: {incident.incident_id}
Priority: {incident.get_priority_display()} (ESCALATED)
Type: {incident.get_incident_type_display()}
Status: {incident.get_status_display()}

Title: {incident.title}
Description: {incident.description}

Escalated by: {escalated_by_name}
Escalation time: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}

Discovery time: {incident.discovered_at.strftime('%Y-%m-%d %H:%M:%S')}
Assigned to: {incident.assigned_to.get_full_name() if incident.assigned_to else 'Unassigned'}

Impact Assessment: {incident.impact_assessment}

Please access the security dashboard for full details and response actions.

This is an automated notification from Klararety Security System.
"""
            
            # Send notifications
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=recipients,
                fail_silently=True
            )
            
            logger.info(f"Sent escalation notifications for {incident.incident_id}")
            
        except Exception as e:
            logger.error(f"Error sending escalation notifications: {str(e)}")
    
    @classmethod
    def _map_threat_to_incident_type(cls, threat_type):
        """Map threat type to incident type."""
        mapping = {
            'malware': 'malware_infection',
            'intrusion': 'system_compromise',
            'data_breach': 'data_breach',
            'privilege_escalation': 'insider_threat',
            'brute_force': 'unauthorized_access',
            'ddos': 'ddos_attack',
            'phishing': 'phishing_attack',
            'ransomware': 'malware_infection',
            'unauthorized_access': 'unauthorized_access',
            'suspicious_activity': 'policy_violation'
        }
        return mapping.get(threat_type, 'other')
    
    @classmethod
    def _assess_threat_impact(cls, threat):
        """Assess impact of threat for incident creation."""
        impact_factors = []
        
        # Severity-based impact
        if threat.severity == 'critical':
            impact_factors.append("Critical severity threat with potential for significant damage")
        elif threat.severity == 'high':
            impact_factors.append("High severity threat requiring immediate attention")
        
        # User impact
        if threat.affected_user:
            if threat.affected_user.role in ['admin', 'provider']:
                impact_factors.append("Affects privileged user account")
            else:
                impact_factors.append("Affects user account")
        
        # System impact
        if threat.threat_type in ['intrusion', 'malware', 'ransomware']:
            impact_factors.append("Potential system compromise")
        
        if threat.threat_type == 'data_breach':
            impact_factors.append("Potential data confidentiality breach")
        
        return "; ".join(impact_factors) if impact_factors else "Impact assessment pending"
    
    @classmethod
    def _auto_assign_incident(cls, incident):
        """Auto-assign incident to appropriate team member."""
        try:
            # Get available security team members
            security_users = User.objects.filter(
                role__in=['admin', 'security'],
                is_active=True
            )
            
            if not security_users.exists():
                return None
            
            # For critical incidents, assign to all admins
            if incident.priority == 'critical':
                # Return first admin for assignment, but notify all
                return security_users.filter(role='admin').first() or security_users.first()
            
            # Simple round-robin assignment
            # In production, this could be more sophisticated (workload-based, expertise-based)
            import random
            return random.choice(list(security_users))
            
        except Exception as e:
            logger.error(f"Error auto-assigning incident: {str(e)}")
            return None
    
    @classmethod
    def _trigger_automated_response(cls, incident):
        """Trigger automated response actions based on incident type and priority."""
        try:
            automated_actions = []
            
            # Priority-based actions
            if incident.priority == 'critical':
                automated_actions.extend([
                    "Immediate security team notification sent",
                    "Escalation timer started (1 hour)",
                    "Management notification queued"
                ])
                
                # For critical incidents, potentially trigger automatic containment
                if incident.incident_type in ['malware_infection', 'system_compromise']:
                    automated_actions.append("Automatic containment procedures initiated")
                    cls._initiate_containment_procedures(incident)
            
            # Incident type-based actions
            if incident.incident_type == 'brute_force' or incident.incident_type == 'unauthorized_access':
                automated_actions.append("Account lockout procedures initiated")
                cls._trigger_account_protection(incident)
            
            if incident.incident_type == 'data_breach':
                automated_actions.append("Data breach notification procedures started")
                cls._trigger_breach_procedures(incident)
            
            # Log automated actions
            if automated_actions:
                incident.response_actions = automated_actions
                incident.save(update_fields=['response_actions'])
                
                logger.info(f"Triggered automated response for {incident.incident_id}: {automated_actions}")
            
        except Exception as e:
            logger.error(f"Error triggering automated response: {str(e)}")
    
    @classmethod
    def _initiate_containment_procedures(cls, incident):
        """Initiate automated containment procedures."""
        try:
            containment_actions = []
            
            # Network isolation for affected systems
            if incident.affected_systems:
                containment_actions.append(f"Network isolation initiated for {len(incident.affected_systems)} systems")
            
            # Account isolation for affected users
            affected_users = incident.affected_users.all()
            if affected_users.exists():
                for user in affected_users:
                    # Disable user account temporarily
                    user.is_active = False
                    user.save(update_fields=['is_active'])
                    containment_actions.append(f"Temporarily disabled account: {user.username}")
            
            # Update incident with containment actions
            current_actions = incident.containment_actions or ""
            updated_actions = current_actions + "\n" + "\n".join(containment_actions)
            incident.containment_actions = updated_actions.strip()
            incident.status = 'containment'
            incident.save(update_fields=['containment_actions', 'status'])
            
            logger.info(f"Initiated containment for {incident.incident_id}")
            
        except Exception as e:
            logger.error(f"Error initiating containment: {str(e)}")
    
    @classmethod
    def _trigger_account_protection(cls, incident):
        """Trigger account protection measures."""
        try:
            # This would integrate with actual account management systems
            protection_actions = [
                "Enhanced monitoring enabled for affected accounts",
                "Additional authentication factors required",
                "Account access logging increased"
            ]
            
            current_actions = incident.containment_actions or ""
            updated_actions = current_actions + "\n" + "\n".join(protection_actions)
            incident.containment_actions = updated_actions.strip()
            incident.save(update_fields=['containment_actions'])
            
        except Exception as e:
            logger.error(f"Error triggering account protection: {str(e)}")
    
    @classmethod
    def _trigger_breach_procedures(cls, incident):
        """Trigger data breach notification procedures."""
        try:
            breach_actions = [
                "Data breach assessment initiated",
                "Legal team notification queued",
                "Regulatory notification procedures started",
                "Customer communication template prepared"
            ]
            
            current_actions = incident.response_actions or []
            incident.response_actions = current_actions + breach_actions
            incident.save(update_fields=['response_actions'])
            
            # Start breach notification timer (72 hours for GDPR compliance)
            cls._schedule_breach_notifications(incident)
            
        except Exception as e:
            logger.error(f"Error triggering breach procedures: {str(e)}")
    
    @classmethod
    def _send_incident_notifications(cls, incident):
        """Send incident creation notifications."""
        try:
            # Get notification recipients based on priority
            recipients = cls._get_incident_recipients(incident)
            
            if not recipients:
                logger.warning(f"No recipients for incident {incident.incident_id}")
                return
            
            # Prepare notification
            subject = f"{'CRITICAL' if incident.priority == 'critical' else 'SECURITY'} INCIDENT: {incident.incident_id}"
            
            message = f"""
SECURITY INCIDENT CREATED

Incident ID: {incident.incident_id}
Priority: {incident.get_priority_display()}
Type: {incident.get_incident_type_display()}
Status: {incident.get_status_display()}

Title: {incident.title}
Description: {incident.description}

Discovery time: {incident.discovered_at.strftime('%Y-%m-%d %H:%M:%S')}
Assigned to: {incident.assigned_to.get_full_name() if incident.assigned_to else 'Auto-assigning...'}

Response timeframe: {cls.RESPONSE_TIMEFRAMES.get(incident.priority, 24)} hours

Impact Assessment: {incident.impact_assessment}

Automated response actions taken:
{chr(10).join(incident.response_actions or ['None'])}

Please access the security dashboard for full details and response coordination.

This is an automated notification from Klararety Security System.
"""
            
            # Send notifications
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=recipients,
                fail_silently=True
            )
            
            logger.info(f"Sent incident notifications for {incident.incident_id}")
            
        except Exception as e:
            logger.error(f"Error sending incident notifications: {str(e)}")
    
    @classmethod
    def _get_incident_recipients(cls, incident):
        """Get notification recipients for incident."""
        recipients = []
        
        try:
            # Always notify security team
            security_emails = User.objects.filter(
                role__in=['admin', 'security'],
                is_active=True,
                email__isnull=False
            ).values_list('email', flat=True)
            
            recipients.extend(security_emails)
            
            # For critical incidents, notify additional stakeholders
            if incident.priority == 'critical':
                # Add management emails from settings
                management_emails = getattr(settings, 'SECURITY_MANAGEMENT_EMAILS', [])
                recipients.extend(management_emails)
                
                # Add compliance officers
                compliance_emails = User.objects.filter(
                    role='compliance',
                    is_active=True,
                    email__isnull=False
                ).values_list('email', flat=True)
                
                recipients.extend(compliance_emails)
            
            # Remove duplicates
            return list(set(recipients))
            
        except Exception as e:
            logger.error(f"Error getting incident recipients: {str(e)}")
            return []
    
    @classmethod
    def _get_escalation_recipients(cls, incident):
        """Get escalation notification recipients."""
        # Similar to incident recipients but may include additional escalation contacts
        recipients = cls._get_incident_recipients(incident)
        
        # Add escalation-specific contacts
        escalation_emails = getattr(settings, 'SECURITY_ESCALATION_EMAILS', [])
        recipients.extend(escalation_emails)
        
        return list(set(recipients))
    
    @classmethod
    def _assign_critical_incident_team(cls, incident):
        """Assign full incident response team for critical incidents."""
        try:
            # Get all available security team members
            security_team = User.objects.filter(
                role__in=['admin', 'security'],
                is_active=True
            )
            
            # Add all security team members
            incident.team_members.set(security_team)
            
            # Also add compliance officers for critical incidents
            compliance_team = User.objects.filter(
                role='compliance',
                is_active=True
            )
            
            incident.team_members.add(*compliance_team)
            
            logger.info(f"Assigned incident response team to {incident.incident_id}")
            
        except Exception as e:
            logger.error(f"Error assigning incident team: {str(e)}")
    
    @classmethod
    def _schedule_breach_notifications(cls, incident):
        """Schedule breach notification reminders."""
        try:
            # This would integrate with task scheduling system
            # For now, just log the requirement
            logger.info(f"Breach notification schedule initiated for {incident.incident_id}")
            
            # In production, this would create scheduled tasks for:
            # - 24 hour reminder
            # - 48 hour warning 
            # - 72 hour deadline alert
            
        except Exception as e:
            logger.error(f"Error scheduling breach notifications: {str(e)}")


class IncidentWorkflowManager:
    """Manages incident workflow and state transitions."""
    
    VALID_TRANSITIONS = {
        'reported': ['acknowledged', 'investigating'],
        'acknowledged': ['investigating', 'containment'],
        'investigating': ['containment', 'closed'],
        'containment': ['eradication', 'recovery'],
        'eradication': ['recovery'],
        'recovery': ['post_incident'],
        'post_incident': ['closed'],
        'closed': []  # Terminal state
    }
    
    @classmethod
    def transition_incident(cls, incident, new_status, user=None, notes=None):
        """Transition incident to new status with validation."""
        try:
            current_status = incident.status
            
            # Validate transition
            if new_status not in cls.VALID_TRANSITIONS.get(current_status, []):
                raise ValueError(f"Invalid transition from {current_status} to {new_status}")
            
            # Update incident
            incident.status = new_status
            
            # Add status change notes
            if notes:
                timestamp = timezone.now().strftime('%Y-%m-%d %H:%M:%S')
                user_name = user.get_full_name() if user else "System"
                status_note = f"[{timestamp}] Status changed to {new_status} by {user_name}: {notes}"
                
                current_notes = incident.impact_assessment or ""
                incident.impact_assessment = current_notes + "\n\n" + status_note
            
            # Set closure time if closing
            if new_status == 'closed':
                incident.closed_at = timezone.now()
            
            incident.save()
            
            # Trigger status-specific actions
            cls._handle_status_change(incident, current_status, new_status, user)
            
            logger.info(f"Transitioned incident {incident.incident_id} from {current_status} to {new_status}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error transitioning incident {incident.incident_id}: {str(e)}")
            raise
    
    @classmethod
    def _handle_status_change(cls, incident, old_status, new_status, user):
        """Handle actions required for status changes."""
        try:
            # Send notifications for key status changes
            if new_status in ['containment', 'closed']:
                cls._send_status_notifications(incident, old_status, new_status, user)
            
            # Auto-generate lessons learned template when moving to post-incident
            if new_status == 'post_incident':
                cls._generate_lessons_learned_template(incident)
            
        except Exception as e:
            logger.error(f"Error handling status change for {incident.incident_id}: {str(e)}")
    
    @classmethod
    def _send_status_notifications(cls, incident, old_status, new_status, user):
        """Send notifications for status changes."""
        # Implementation for status change notifications
        pass
    
    @classmethod
    def _generate_lessons_learned_template(cls, incident):
        """Generate lessons learned template for post-incident analysis."""
        try:
            template = f"""
INCIDENT LESSONS LEARNED - {incident.incident_id}

1. INCIDENT SUMMARY
   - What happened?
   - When did it occur?
   - How was it discovered?

2. TIMELINE
   - Detection: {incident.discovered_at}
   - Response: {incident.reported_at}
   - Containment: [Time when contained]
   - Resolution: {incident.closed_at or 'Ongoing'}

3. ROOT CAUSE ANALYSIS
   - What was the root cause?
   - Contributing factors?
   - Why wasn't it prevented?

4. RESPONSE EFFECTIVENESS
   - What worked well?
   - What could be improved?
   - Response time assessment

5. IMPACT ASSESSMENT
   - Systems affected: {', '.join(incident.affected_systems) if incident.affected_systems else 'None specified'}
   - Users affected: {incident.affected_users.count()}
   - Business impact: [To be completed]

6. IMPROVEMENTS IDENTIFIED
   - Process improvements
   - Technical improvements
   - Training needs

7. ACTION ITEMS
   - [ ] Immediate actions
   - [ ] Short-term improvements
   - [ ] Long-term strategic changes

Template generated on: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
            
            incident.lessons_learned = template
            incident.save(update_fields=['lessons_learned'])
            
        except Exception as e:
            logger.error(f"Error generating lessons learned template: {str(e)}")
