# services/system_integration.py
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from django.utils import timezone
from django.db import transaction
from django.conf import settings
from django.core.cache import cache

from medication.services.enhanced_adherence_service import EnhancedAdherenceService
from fhir.services.advanced_integration_service import AdvancedFHIRIntegrationService
from telemedicine.services.enhanced_telemedicine import EnhancedTelemedicineService
from users.services.clinical_trials_service import ResearchClinicalTrialsService
from wearables.services.notification_service import WearableNotificationService

logger = logging.getLogger(__name__)

class RareDiseaseSystemIntegration:
    """
    Central integration service for rare disease healthcare system.
    Coordinates all enhanced features and ensures data consistency.
    """
    
    def __init__(self):
        self.adherence_service = EnhancedAdherenceService()
        self.fhir_service = AdvancedFHIRIntegrationService()
        self.telemedicine_service = EnhancedTelemedicineService()
        self.research_service = ResearchClinicalTrialsService()
        self.notification_service = WearableNotificationService()
    
    def create_comprehensive_patient_profile(self, patient_id: int, initial_data: Dict) -> Dict:
        """
        Create comprehensive patient profile with all enhanced features enabled.
        Sets up medication adherence, wearable integration, and research eligibility.
        """
        from django.contrib.auth import get_user_model
        User = get_user_model()
        
        try:
            patient = User.objects.get(id=patient_id, role='patient')
            
            profile_setup = {
                'patient_id': patient_id,
                'setup_timestamp': timezone.now().isoformat(),
                'features_enabled': [],
                'integrations_configured': [],
                'errors': []
            }
            
            with transaction.atomic():
                # 1. Set up medication adherence intelligence
                if initial_data.get('medications'):
                    try:
                        for medication_data in initial_data['medications']:
                            medication = self._create_or_update_medication(patient, medication_data)
                            schedule_result = EnhancedAdherenceService.create_intelligent_reminder_schedule(medication)
                            if schedule_result:
                                profile_setup['features_enabled'].append('intelligent_medication_reminders')
                    except Exception as e:
                        profile_setup['errors'].append(f"Medication setup error: {str(e)}")
                
                # 2. Configure wearable device integrations
                if initial_data.get('wearable_devices'):
                    try:
                        for device_data in initial_data['wearable_devices']:
                            integration_result = self._setup_wearable_integration(patient, device_data)
                            if integration_result['status'] == 'success':
                                profile_setup['integrations_configured'].append(f"wearable_{device_data['type']}")
                    except Exception as e:
                        profile_setup['errors'].append(f"Wearable setup error: {str(e)}")
                
                # 3. Set up FHIR data exchange capabilities
                try:
                    fhir_patient = self._initialize_fhir_patient_record(patient, initial_data.get('external_records'))
                    if fhir_patient:
                        profile_setup['features_enabled'].append('fhir_data_exchange')
                except Exception as e:
                    profile_setup['errors'].append(f"FHIR setup error: {str(e)}")
                
                # 4. Configure telemedicine capabilities
                try:
                    telemedicine_setup = self._setup_telemedicine_preferences(patient, initial_data.get('telemedicine_preferences', {}))
                    if telemedicine_setup:
                        profile_setup['features_enabled'].append('enhanced_telemedicine')
                except Exception as e:
                    profile_setup['errors'].append(f"Telemedicine setup error: {str(e)}")
                
                # 5. Assess research study eligibility
                try:
                    research_eligibility = self._assess_research_eligibility(patient, initial_data.get('conditions', []))
                    profile_setup['research_eligibility'] = research_eligibility
                    if research_eligibility['eligible_studies_count'] > 0:
                        profile_setup['features_enabled'].append('research_participation')
                except Exception as e:
                    profile_setup['errors'].append(f"Research assessment error: {str(e)}")
                
                # 6. Set up automated health monitoring
                try:
                    monitoring_setup = self._configure_health_monitoring(patient, initial_data.get('monitoring_preferences', {}))
                    if monitoring_setup:
                        profile_setup['features_enabled'].append('automated_health_monitoring')
                except Exception as e:
                    profile_setup['errors'].append(f"Health monitoring setup error: {str(e)}")
            
            # Cache the profile setup for quick access
            cache.set(f"patient_profile_setup_{patient_id}", profile_setup, timeout=3600)
            
            return {
                'status': 'success' if not profile_setup['errors'] else 'partial_success',
                'profile_setup': profile_setup,
                'next_steps': self._generate_next_steps(profile_setup),
                'message': f"Patient profile setup completed with {len(profile_setup['features_enabled'])} features enabled"
            }
            
        except Exception as e:
            logger.error(f"Error creating comprehensive patient profile: {str(e)}")
            return {'status': 'error', 'message': str(e)}
    
    def process_daily_patient_workflow(self, patient_id: int) -> Dict:
        """
        Process daily workflow for rare disease patient including:
        - Medication adherence checks
        - Wearable data analysis
        - Health alerts generation
        - Research data collection
        """
        from django.contrib.auth import get_user_model
        User = get_user_model()
        
        try:
            patient = User.objects.get(id=patient_id, role='patient')
            
            workflow_results = {
                'patient_id': patient_id,
                'workflow_date': timezone.now().date().isoformat(),
                'completed_tasks': [],
                'alerts_generated': [],
                'recommendations': [],
                'errors': []
            }
            
            # 1. Process medication adherence
            try:
                adherence_analysis = EnhancedAdherenceService.analyze_adherence_trends(patient_id, days=7)
                if adherence_analysis['status'] == 'success':
                    workflow_results['completed_tasks'].append('medication_adherence_analysis')
                    
                    # Generate alerts for poor adherence
                    if adherence_analysis['overall_adherence'] < 80:
                        workflow_results['alerts_generated'].append({
                            'type': 'adherence_concern',
                            'severity': 'medium',
                            'message': f"Medication adherence dropped to {adherence_analysis['overall_adherence']}%"
                        })
                        
                        # Create intervention if needed
                        if adherence_analysis['overall_adherence'] < 60:
                            for med in adherence_analysis.get('problematic_medications', []):
                                intervention = EnhancedAdherenceService.create_adherence_intervention(
                                    patient_id, med.get('medication_id')
                                )
                                workflow_results['completed_tasks'].append('adherence_intervention_created')
                    
                    workflow_results['recommendations'].extend(adherence_analysis.get('recommendations', []))
            except Exception as e:
                workflow_results['errors'].append(f"Adherence processing error: {str(e)}")
            
            # 2. Analyze wearable data for health insights
            try:
                wearable_analysis = self._analyze_daily_wearable_data(patient)
                if wearable_analysis['status'] == 'success':
                    workflow_results['completed_tasks'].append('wearable_data_analysis')
                    
                    # Generate health alerts from wearable data
                    for alert in wearable_analysis.get('health_alerts', []):
                        workflow_results['alerts_generated'].append(alert)
                    
                    workflow_results['recommendations'].extend(wearable_analysis.get('recommendations', []))
            except Exception as e:
                workflow_results['errors'].append(f"Wearable analysis error: {str(e)}")
            
            # 3. Check for upcoming appointments and prepare data
            try:
                upcoming_appointments = self._check_upcoming_appointments(patient)
                for appointment in upcoming_appointments:
                    if appointment['days_until'] <= 1:  # Tomorrow or today
                        prep_result = EnhancedTelemedicineService.prepare_pre_visit_data_collection(
                            appointment['encounter_id']
                        )
                        if prep_result['status'] == 'success':
                            workflow_results['completed_tasks'].append('appointment_data_preparation')
            except Exception as e:
                workflow_results['errors'].append(f"Appointment preparation error: {str(e)}")
            
            # 4. Process research data collection
            try:
                research_collections = self._process_research_data_collection(patient)
                if research_collections:
                    workflow_results['completed_tasks'].append('research_data_collection')
                    workflow_results['research_contributions'] = len(research_collections)
            except Exception as e:
                workflow_results['errors'].append(f"Research data collection error: {str(e)}")
            
            # 5. Generate personalized health summary
            try:
                health_summary = self._generate_daily_health_summary(patient, workflow_results)
                workflow_results['daily_health_summary'] = health_summary
                workflow_results['completed_tasks'].append('daily_health_summary')
            except Exception as e:
                workflow_results['errors'].append(f"Health summary error: {str(e)}")
            
            # 6. Send summary notification to patient
            try:
                if workflow_results['alerts_generated']:
                    summary_notification = self._send_daily_summary_notification(patient, workflow_results)
                    if summary_notification:
                        workflow_results['completed_tasks'].append('summary_notification_sent')
            except Exception as e:
                workflow_results['errors'].append(f"Notification sending error: {str(e)}")
            
            return {
                'status': 'success' if not workflow_results['errors'] else 'partial_success',
                'workflow_results': workflow_results,
                'summary': {
                    'total_tasks': len(workflow_results['completed_tasks']),
                    'alerts_count': len(workflow_results['alerts_generated']),
                    'recommendations_count': len(workflow_results['recommendations'])
                }
            }
            
        except Exception as e:
            logger.error(f"Error processing daily patient workflow: {str(e)}")
            return {'status': 'error', 'message': str(e)}
    
    def coordinate_care_team_communication(self, patient_id: int, event_type: str, event_data: Dict) -> Dict:
        """
        Coordinate communication between patient's care team (providers, caregivers, researchers).
        Ensures all relevant parties are informed of important health events.
        """
        from django.contrib.auth import get_user_model
        from users.models import ConsentRecord
        User = get_user_model()
        
        try:
            patient = User.objects.get(id=patient_id, role='patient')
            
            communication_result = {
                'patient_id': patient_id,
                'event_type': event_type,
                'timestamp': timezone.now().isoformat(),
                'notifications_sent': [],
                'failed_notifications': [],
                'care_team_notified': []
            }
            
            # 1. Identify care team members
            care_team = self._get_patient_care_team(patient)
            
            # 2. Determine who should be notified based on event type and consent
            notification_rules = self._get_notification_rules_for_event(event_type, event_data)
            
            # 3. Send notifications to appropriate care team members
            for team_member in care_team:
                should_notify = self._should_notify_team_member(
                    team_member, event_type, notification_rules, patient
                )
                
                if should_notify:
                    try:
                        notification_sent = self._send_care_team_notification(
                            team_member, patient, event_type, event_data
                        )
                        
                        if notification_sent:
                            communication_result['notifications_sent'].append({
                                'recipient_id': team_member['user_id'],
                                'recipient_role': team_member['role'],
                                'notification_method': team_member['preferred_method']
                            })
                            communication_result['care_team_notified'].append(team_member['name'])
                        else:
                            communication_result['failed_notifications'].append({
                                'recipient_id': team_member['user_id'],
                                'reason': 'delivery_failed'
                            })
                    except Exception as e:
                        communication_result['failed_notifications'].append({
                            'recipient_id': team_member['user_id'],
                            'reason': str(e)
                        })
            
            # 4. Log communication in patient record
            self._log_care_team_communication(patient, event_type, communication_result)
            
            return {
                'status': 'success',
                'communication_result': communication_result,
                'summary': f"Notified {len(communication_result['notifications_sent'])} care team members"
            }
            
        except Exception as e:
            logger.error(f"Error coordinating care team communication: {str(e)}")
            return {'status': 'error', 'message': str(e)}
    
    def generate_comprehensive_patient_report(self, patient_id: int, report_type: str = 'comprehensive') -> Dict:
        """
        Generate comprehensive patient report including all system data.
        Used for provider visits, research submissions, or patient summaries.
        """
        from django.contrib.auth import get_user_model
        User = get_user_model()
        
        try:
            patient = User.objects.get(id=patient_id, role='patient')
            
            report_data = {
                'patient_id': patient_id,
                'report_type': report_type,
                'generated_at': timezone.now().isoformat(),
                'report_period': {
                    'start_date': (timezone.now() - timedelta(days=90)).date().isoformat(),
                    'end_date': timezone.now().date().isoformat()
                },
                'sections': {}
            }
            
            # 1. Patient Demographics and Basic Info
            report_data['sections']['demographics'] = self._get_patient_demographics(patient)
            
            # 2. Medication Adherence Analysis
            adherence_analysis = EnhancedAdherenceService.analyze_adherence_trends(patient_id, days=90)
            report_data['sections']['medication_adherence'] = adherence_analysis
            
            # 3. Wearable Data Summary
            wearable_summary = self._get_comprehensive_wearable_summary(patient)
            report_data['sections']['wearable_data'] = wearable_summary
            
            # 4. Telemedicine Encounters Summary
            telemedicine_summary = self._get_telemedicine_encounters_summary(patient)
            report_data['sections']['telemedicine_encounters'] = telemedicine_summary
            
            # 5. Research Participation Summary
            research_summary = self._get_research_participation_summary(patient)
            report_data['sections']['research_participation'] = research_summary
            
            # 6. FHIR Data Export (if requested)
            if report_type in ['comprehensive', 'external_sharing']:
                fhir_bundle = self.fhir_service.export_patient_data_bundle(patient_id, include_family_history=True)
                report_data['sections']['fhir_export'] = fhir_bundle
            
            # 7. Clinical Alerts and Recommendations
            clinical_alerts = self._get_clinical_alerts_summary(patient)
            report_data['sections']['clinical_alerts'] = clinical_alerts
            
            # 8. Health Trends Analysis
            health_trends = self._analyze_comprehensive_health_trends(patient)
            report_data['sections']['health_trends'] = health_trends
            
            return {
                'status': 'success',
                'report': report_data,
                'export_formats': ['pdf', 'fhir_bundle', 'hl7', 'json'],
                'sharing_options': ['provider_portal', 'patient_portal', 'research_database', 'external_ehr']
            }
            
        except Exception as e:
            logger.error(f"Error generating comprehensive patient report: {str(e)}")
            return {'status': 'error', 'message': str(e)}
    
    def emergency_health_alert_workflow(self, patient_id: int, alert_data: Dict) -> Dict:
        """
        Process emergency health alerts with immediate care team notification.
        Coordinates rapid response for critical health events.
        """
        from django.contrib.auth import get_user_model
        User = get_user_model()
        
        try:
            patient = User.objects.get(id=patient_id, role='patient')
            
            emergency_response = {
                'patient_id': patient_id,
                'alert_timestamp': timezone.now().isoformat(),
                'alert_type': alert_data.get('type', 'unknown'),
                'severity': alert_data.get('severity', 'high'),
                'immediate_actions': [],
                'care_team_notified': [],
                'emergency_contacts_notified': [],
                'escalation_triggered': False
            }
            
            with transaction.atomic():
                # 1. Log emergency alert
                self._log_emergency_alert(patient, alert_data)
                emergency_response['immediate_actions'].append('emergency_alert_logged')
                
                # 2. Send immediate notifications to primary care team
                primary_care_team = self._get_primary_care_team(patient)
                for team_member in primary_care_team:
                    notification_sent = self._send_emergency_notification(
                        team_member, patient, alert_data
                    )
                    if notification_sent:
                        emergency_response['care_team_notified'].append(team_member['name'])
                
                emergency_response['immediate_actions'].append('primary_care_team_notified')
                
                # 3. Notify emergency contacts if severe
                if alert_data.get('severity') in ['critical', 'life_threatening']:
                    emergency_contacts = self._get_emergency_contacts(patient)
                    for contact in emergency_contacts:
                        contact_notified = self._notify_emergency_contact(contact, patient, alert_data)
                        if contact_notified:
                            emergency_response['emergency_contacts_notified'].append(contact['name'])
                    
                    emergency_response['immediate_actions'].append('emergency_contacts_notified')
                    emergency_response['escalation_triggered'] = True
                
                # 4. Collect immediate health data
                immediate_data = self._collect_immediate_health_data(patient)
                if immediate_data:
                    emergency_response['immediate_health_data'] = immediate_data
                    emergency_response['immediate_actions'].append('immediate_health_data_collected')
                
                # 5. Generate emergency FHIR bundle for potential hospital transfer
                if alert_data.get('severity') == 'critical':
                    emergency_fhir = self.fhir_service.export_patient_data_bundle(
                        patient_id, include_family_history=False
                    )
                    emergency_response['emergency_fhir_bundle'] = emergency_fhir['bundle']['id']
                    emergency_response['immediate_actions'].append('emergency_fhir_bundle_prepared')
                
                # 6. Update patient status and create care plan
                care_plan_updated = self._update_emergency_care_plan(patient, alert_data)
                if care_plan_updated:
                    emergency_response['immediate_actions'].append('emergency_care_plan_updated')
            
            return {
                'status': 'success',
                'emergency_response': emergency_response,
                'follow_up_required': True,
                'next_steps': [
                    'Monitor patient status continuously',
                    'Follow up with notified care team members',
                    'Document emergency response outcomes',
                    'Review and update emergency protocols if needed'
                ]
            }
            
        except Exception as e:
            logger.error(f"Error processing emergency health alert: {str(e)}")
            return {'status': 'error', 'message': str(e)}
    
    # Helper methods (implementations would be added based on your specific models)
    def _create_or_update_medication(self, patient, medication_data):
        """Create or update medication record."""
        # Implementation using your Medication model
        pass
    
    def _setup_wearable_integration(self, patient, device_data):
        """Set up wearable device integration."""
        # Implementation using your WearableIntegration model
        pass
    
    def _initialize_fhir_patient_record(self, patient, external_records):
        """Initialize FHIR patient record."""
        # Implementation using your FHIR models
        pass
    
    def _setup_telemedicine_preferences(self, patient, preferences):
        """Set up telemedicine preferences."""
        # Implementation for telemedicine setup
        pass
    
    def _assess_research_eligibility(self, patient, conditions):
        """Assess patient eligibility for research studies."""
        # Implementation using your research models
        pass
    
    def _configure_health_monitoring(self, patient, preferences):
        """Configure automated health monitoring."""
        # Implementation for health monitoring setup
        pass
    
    def _generate_next_steps(self, profile_setup):
        """Generate next steps based on profile setup results."""
        next_steps = []
        
        if 'intelligent_medication_reminders' in profile_setup['features_enabled']:
            next_steps.append('Test medication reminders on connected devices')
        
        if 'fhir_data_exchange' in profile_setup['features_enabled']:
            next_steps.append('Request external health records import')
        
        if 'research_participation' in profile_setup['features_enabled']:
            next_steps.append('Review available research studies')
        
        if not next_steps:
            next_steps.append('Complete any remaining profile information')
        
        return next_steps