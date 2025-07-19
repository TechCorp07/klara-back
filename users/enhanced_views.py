# users/views/enhanced_views.py
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from django.db import transaction
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.db.models import Avg, Max, Min, Count

from users.permissions import IsApprovedUser
from medication.services.enhanced_adherence_service import EnhancedAdherenceService
from fhir.services.advanced_integration_service import AdvancedFHIRIntegrationService
from telemedicine.services.enhanced_telemedicine import EnhancedTelemedicineService
from users.services.clinical_trials_service import ResearchClinicalTrialsService


class EnhancedMedicationViewSet(viewsets.ViewSet):
    """
    Enhanced medication management with intelligent adherence features.
    Builds on your existing medication models and APIs.
    """
    permission_classes = [IsAuthenticated, IsApprovedUser]
    
    @swagger_auto_schema(
        method='post',
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'medication_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'patient_id': openapi.Schema(type=openapi.TYPE_INTEGER, required=False)
            }
        ),
        responses={200: 'Adherence schedule created successfully'}
    )
    @action(detail=False, methods=['post'])
    def create_intelligent_reminder_schedule(self, request):
        """Create personalized medication reminder schedule using AI insights."""
        medication_id = request.data.get('medication_id')
        patient_id = request.data.get('patient_id', request.user.id)
        
        # Permission check: patients can only access their own data
        if request.user.role == 'patient' and patient_id != request.user.id:
            return Response(
                {'error': 'Unauthorized access to patient data'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        try:
            from medication.models import Medication
            medication = Medication.objects.get(id=medication_id, patient_id=patient_id)
            
            # Create intelligent reminder schedule
            schedule_result = EnhancedAdherenceService.create_intelligent_reminder_schedule(medication)
            
            return Response({
                'status': 'success',
                'medication_id': medication_id,
                'reminder_schedule': schedule_result,
                'message': 'Intelligent reminder schedule created'
            })
            
        except Medication.DoesNotExist:
            return Response(
                {'error': 'Medication not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @swagger_auto_schema(
        method='post',
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'study_id': openapi.Schema(type=openapi.TYPE_STRING),
                'analytics_type': openapi.Schema(type=openapi.TYPE_STRING, enum=['comprehensive', 'summary', 'trends'])
            }
        ),
        responses={200: 'Research analytics generated successfully'}
    )
    @action(detail=False, methods=['post'])
    def generate_research_analytics(self, request):
        """Generate analytics and insights for research study."""
        study_id = request.data.get('study_id')
        analytics_type = request.data.get('analytics_type', 'comprehensive')
        
        # Permission check: only researchers can generate analytics
        if request.user.role != 'researcher':
            return Response(
                {'error': 'Only researchers can generate analytics'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        try:
            result = ResearchClinicalTrialsService.generate_research_analytics(
                study_id, request.user.id, analytics_type
            )
            
            return Response(result)
            
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class EnhancedNotificationViewSet(viewsets.ViewSet):
    """
    Enhanced notification system for wearable devices and patient engagement.
    Builds on your existing NotificationDelivery model.
    """
    permission_classes = [IsAuthenticated, IsApprovedUser]
    
    @swagger_auto_schema(
        method='post',
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'patient_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'notification_type': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    enum=['medication_reminder', 'appointment_reminder', 'vitals_request', 'emergency_alert']
                ),
                'title': openapi.Schema(type=openapi.TYPE_STRING),
                'message': openapi.Schema(type=openapi.TYPE_STRING),
                'priority': openapi.Schema(type=openapi.TYPE_STRING, enum=['low', 'normal', 'high', 'critical']),
                'schedule_time': openapi.Schema(type=openapi.TYPE_STRING, format='datetime', required=False)
            }
        ),
        responses={200: 'Notification sent successfully'}
    )
    @action(detail=False, methods=['post'])
    def send_wearable_notification(self, request):
        """Send notification to patient's wearable devices."""
        patient_id = request.data.get('patient_id')
        notification_data = request.data
        
        # Permission check
        if request.user.role == 'patient' and patient_id != request.user.id:
            return Response(
                {'error': 'Unauthorized access'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        if request.user.role not in ['patient', 'provider', 'caregiver', 'admin']:
            return Response(
                {'error': 'Insufficient permissions'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        try:
            from wearables.services.notification_service import WearableNotificationService
            from wearables.models import WearableIntegration
            
            # Get patient's wearable devices
            devices = WearableIntegration.objects.filter(
                user_id=patient_id,
                status=WearableIntegration.ConnectionStatus.CONNECTED
            )
            
            if not devices.exists():
                return Response({
                    'status': 'warning',
                    'message': 'No connected wearable devices found for patient'
                })
            
            notifications_sent = 0
            for device in devices:
                success = WearableNotificationService.send_watch_notification(
                    device_id=device.platform_user_id,
                    title=notification_data['title'],
                    message=notification_data['message'],
                    is_critical=notification_data.get('priority') == 'critical'
                )
                
                if success:
                    notifications_sent += 1
            
            return Response({
                'status': 'success',
                'notifications_sent': notifications_sent,
                'total_devices': devices.count(),
                'message': f'Notification sent to {notifications_sent} of {devices.count()} devices'
            })
            
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @swagger_auto_schema(
        method='get',
        manual_parameters=[
            openapi.Parameter('patient_id', openapi.IN_QUERY, type=openapi.TYPE_INTEGER, required=False),
            openapi.Parameter('days', openapi.IN_QUERY, type=openapi.TYPE_INTEGER, required=False)
        ],
        responses={200: 'Notification analytics retrieved successfully'}
    )
    @action(detail=False, methods=['get'])
    def get_notification_analytics(self, request):
        """Get notification delivery analytics for patient or provider."""
        patient_id = request.query_params.get('patient_id')
        days = int(request.query_params.get('days', 30))
        
        if request.user.role == 'patient':
            patient_id = request.user.id
        
        try:
            from wearables.models import NotificationDelivery
            
            # Get notification delivery data
            notifications = NotificationDelivery.objects.filter(
                user_id=patient_id,
                sent_at__gte=timezone.now() - timezone.timedelta(days=days)
            )
            
            analytics = {
                'total_notifications': notifications.count(),
                'successful_deliveries': notifications.filter(success=True).count(),
                'response_rate': notifications.filter(user_response__isnull=False).count(),
                'notification_types': dict(notifications.values_list('notification_type').annotate(count=Count('id'))),
                'engagement_metrics': {
                    'delivered_count': notifications.filter(delivered_at__isnull=False).count(),
                    'read_count': notifications.filter(read_at__isnull=False).count(),
                    'responded_count': notifications.filter(user_response__isnull=False).count()
                }
            }
            
            # Calculate rates
            if analytics['total_notifications'] > 0:
                analytics['delivery_rate'] = (analytics['successful_deliveries'] / analytics['total_notifications']) * 100
                analytics['engagement_rate'] = (analytics['engagement_metrics']['read_count'] / analytics['total_notifications']) * 100
                analytics['response_rate_percentage'] = (analytics['response_rate'] / analytics['total_notifications']) * 100
            
            return Response({
                'status': 'success',
                'analytics': analytics,
                'period_days': days
            })
            
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class EnhancedWearableDataViewSet(viewsets.ViewSet):
    """
    Enhanced wearable data collection and analysis.
    Builds on your existing WearableMeasurement model.
    """
    permission_classes = [IsAuthenticated, IsApprovedUser]
    
    @swagger_auto_schema(
        method='post',
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'patient_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'start_date': openapi.Schema(type=openapi.TYPE_STRING, format='date'),
                'end_date': openapi.Schema(type=openapi.TYPE_STRING, format='date'),
                'measurement_types': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Schema(type=openapi.TYPE_STRING))
            }
        ),
        responses={200: 'Wearable data analyzed successfully'}
    )
    @action(detail=False, methods=['post'])
    def analyze_wearable_trends(self, request):
        """Analyze wearable data trends for health insights."""
        patient_id = request.data.get('patient_id', request.user.id)
        start_date = request.data.get('start_date')
        end_date = request.data.get('end_date')
        measurement_types = request.data.get('measurement_types', [])
        
        # Permission check
        if request.user.role == 'patient' and patient_id != request.user.id:
            return Response(
                {'error': 'Unauthorized access'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        try:
            from wearables.models import WearableMeasurement
            from datetime import datetime

            
            # Parse dates
            start_dt = datetime.fromisoformat(start_date) if start_date else timezone.now() - timezone.timedelta(days=30)
            end_dt = datetime.fromisoformat(end_date) if end_date else timezone.now()
            
            # Get measurements
            measurements = WearableMeasurement.objects.filter(
                user_id=patient_id,
                measured_at__range=[start_dt, end_dt]
            )
            
            if measurement_types:
                measurements = measurements.filter(measurement_type__in=measurement_types)
            
            if not measurements.exists():
                return Response({
                    'status': 'warning',
                    'message': 'No wearable data found for the specified period'
                })
            
            # Analyze trends
            trends_analysis = {}
            for measurement_type in measurements.values_list('measurement_type', flat=True).distinct():
                type_measurements = measurements.filter(measurement_type=measurement_type)
                
                trends_analysis[measurement_type] = {
                    'count': type_measurements.count(),
                    'average': type_measurements.aggregate(avg=Avg('value'))['avg'],
                    'min': type_measurements.aggregate(min=Min('value'))['min'],
                    'max': type_measurements.aggregate(max=Max('value'))['max'],
                    'unit': type_measurements.first().unit,
                    'trend_direction': self._calculate_trend_direction(type_measurements),
                    'data_quality': self._assess_data_quality(type_measurements)
                }
            
            return Response({
                'status': 'success',
                'patient_id': patient_id,
                'analysis_period': {
                    'start_date': start_dt.isoformat(),
                    'end_date': end_dt.isoformat(),
                    'days': (end_dt - start_dt).days
                },
                'trends_analysis': trends_analysis,
                'health_insights': self._generate_health_insights(trends_analysis),
                'recommendations': self._generate_wearable_recommendations(trends_analysis)
            })
            
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @classmethod
    def _calculate_trend_direction(cls, measurements):
        """Calculate trend direction for measurements."""
        if measurements.count() < 2:
            return 'insufficient_data'
        
        # Simple trend calculation - could be enhanced with more sophisticated algorithms
        first_half = measurements[:measurements.count()//2]
        second_half = measurements[measurements.count()//2:]
        
        first_avg = first_half.aggregate(avg=Avg('value'))['avg']
        second_avg = second_half.aggregate(avg=Avg('value'))['avg']
        
        if second_avg > first_avg * 1.05:  # 5% increase threshold
            return 'increasing'
        elif second_avg < first_avg * 0.95:  # 5% decrease threshold
            return 'decreasing'
        else:
            return 'stable'
    
    @classmethod
    def _assess_data_quality(cls, measurements):
        """Assess quality of wearable data."""
        total_expected = (measurements.last().measured_at - measurements.first().measured_at).days
        actual_measurements = measurements.count()
        
        if total_expected == 0:
            return 'excellent'
        
        completion_rate = actual_measurements / total_expected
        
        if completion_rate >= 0.9:
            return 'excellent'
        elif completion_rate >= 0.7:
            return 'good'
        elif completion_rate >= 0.5:
            return 'fair'
        else:
            return 'poor'
    
    @classmethod
    def _generate_health_insights(cls, trends_analysis):
        """Generate health insights from trends analysis."""
        insights = []
        
        # Heart rate insights
        if 'heart_rate' in trends_analysis:
            hr_data = trends_analysis['heart_rate']
            if hr_data['average'] > 100:
                insights.append('Elevated average heart rate detected - consider consulting healthcare provider')
            elif hr_data['trend_direction'] == 'increasing':
                insights.append('Heart rate showing increasing trend - monitor closely')
        
        # Steps insights
        if 'steps' in trends_analysis:
            steps_data = trends_analysis['steps']
            if steps_data['average'] < 5000:
                insights.append('Low daily step count - consider increasing physical activity')
            elif steps_data['trend_direction'] == 'increasing':
                insights.append('Great job! Your activity levels are improving')
        
        # Sleep insights
        if 'sleep' in trends_analysis:
            sleep_data = trends_analysis['sleep']
            if sleep_data['average'] < 7:
                insights.append('Sleep duration below recommended 7-9 hours - prioritize better sleep habits')
        
        return insights
    
    @classmethod
    def _generate_wearable_recommendations(cls, trends_analysis):
        """Generate recommendations based on wearable data analysis."""
        recommendations = []
        
        # Data quality recommendations
        poor_quality_metrics = [k for k, v in trends_analysis.items() if v['data_quality'] == 'poor']
        if poor_quality_metrics:
            recommendations.append(f"Improve data collection for: {', '.join(poor_quality_metrics)}")
        
        # Health recommendations
        if any(v['trend_direction'] == 'decreasing' for v in trends_analysis.values() if 'steps' in v):
            recommendations.append("Consider setting daily activity goals to maintain fitness levels")
        
        if not recommendations:
            recommendations.append("Continue monitoring your health metrics regularly")
        
        return recommendations
    
    @swagger_auto_schema(
        method='post',
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'medication_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'reminder_type': openapi.Schema(type=openapi.TYPE_STRING, enum=['standard', 'critical', 'gentle'])
            }
        ),
        responses={200: 'Reminder sent successfully'}
    )
    @action(detail=False, methods=['post'])
    def send_intelligent_reminder(self, request):
        """Send personalized medication reminder to patient's devices."""
        medication_id = request.data.get('medication_id')
        reminder_type = request.data.get('reminder_type', 'standard')
        
        try:
            from medication.models import Medication
            medication = Medication.objects.get(id=medication_id)
            
            # Permission check
            if request.user.role == 'patient' and medication.patient != request.user:
                return Response(
                    {'error': 'Unauthorized access'},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            # Send intelligent reminder
            success = EnhancedAdherenceService.send_intelligent_reminder(medication, reminder_type)
            
            return Response({
                'status': 'success' if success else 'partial_success',
                'reminder_sent': success,
                'medication_name': medication.name,
                'reminder_type': reminder_type
            })
            
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @swagger_auto_schema(
        method='get',
        manual_parameters=[
            openapi.Parameter('patient_id', openapi.IN_QUERY, type=openapi.TYPE_INTEGER, required=False),
            openapi.Parameter('days', openapi.IN_QUERY, type=openapi.TYPE_INTEGER, required=False)
        ],
        responses={200: 'Adherence trends retrieved successfully'}
    )
    @action(detail=False, methods=['get'])
    def analyze_adherence_trends(self, request):
        """Analyze medication adherence trends with AI insights."""
        patient_id = request.query_params.get('patient_id', request.user.id)
        days = int(request.query_params.get('days', 30))
        
        # Permission check
        if request.user.role == 'patient' and int(patient_id) != request.user.id:
            return Response(
                {'error': 'Unauthorized access'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        try:
            trends = EnhancedAdherenceService.analyze_adherence_trends(int(patient_id), days)
            return Response(trends)
            
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @swagger_auto_schema(
        method='post',
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'patient_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'medication_id': openapi.Schema(type=openapi.TYPE_INTEGER)
            }
        ),
        responses={200: 'Intervention created successfully'}
    )
    @action(detail=False, methods=['post'])
    def create_adherence_intervention(self, request):
        """Create targeted intervention for patients with poor adherence."""
        patient_id = request.data.get('patient_id')
        medication_id = request.data.get('medication_id')
        
        # Permission check: only providers and admins can create interventions
        if request.user.role not in ['provider', 'admin', 'superadmin']:
            return Response(
                {'error': 'Insufficient permissions'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        try:
            intervention = EnhancedAdherenceService.create_adherence_intervention(patient_id, medication_id)
            return Response(intervention)
            
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class EnhancedFHIRViewSet(viewsets.ViewSet):
    """
    Enhanced FHIR integration for patient data exchange.
    Builds on your existing FHIR models.
    """
    permission_classes = [IsAuthenticated, IsApprovedUser]
    
    @swagger_auto_schema(
        method='post',
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'patient_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'include_family_history': openapi.Schema(type=openapi.TYPE_BOOLEAN, default=False),
                'destination': openapi.Schema(type=openapi.TYPE_STRING, required=False)
            }
        ),
        responses={200: 'FHIR bundle exported successfully'}
    )
    @action(detail=False, methods=['post'])
    def export_patient_bundle(self, request):
        """Export comprehensive patient data as FHIR Bundle."""
        patient_id = request.data.get('patient_id')
        include_family_history = request.data.get('include_family_history', False)
        
        # Permission check
        if request.user.role == 'patient' and patient_id != request.user.id:
            return Response(
                {'error': 'Unauthorized access'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        try:
            fhir_service = AdvancedFHIRIntegrationService()
            result = fhir_service.export_patient_data_bundle(patient_id, include_family_history)
            
            return Response(result)
            
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @swagger_auto_schema(
        method='post',
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'patient_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'fhir_bundle': openapi.Schema(type=openapi.TYPE_OBJECT),
                'source_institution': openapi.Schema(type=openapi.TYPE_STRING)
            }
        ),
        responses={200: 'FHIR data imported successfully'}
    )
    @action(detail=False, methods=['post'])
    def import_external_data(self, request):
        """Import patient data from external FHIR-compliant systems."""
        patient_id = request.data.get('patient_id')
        fhir_bundle = request.data.get('fhir_bundle')
        source_institution = request.data.get('source_institution', 'External System')
        
        # Permission check: only providers and admins can import data
        if request.user.role not in ['provider', 'admin', 'superadmin']:
            return Response(
                {'error': 'Insufficient permissions'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        try:
            fhir_service = AdvancedFHIRIntegrationService()
            result = fhir_service.import_external_patient_data(patient_id, fhir_bundle, source_institution)
            
            return Response(result)
            
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @swagger_auto_schema(
        method='post',
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'condition_code': openapi.Schema(type=openapi.TYPE_STRING),
                'patient_ids': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Schema(type=openapi.TYPE_INTEGER), required=False)
            }
        ),
        responses={200: 'Research bundle created successfully'}
    )
    @action(detail=False, methods=['post'])
    def create_research_bundle(self, request):
        """Create anonymized research bundle for rare disease studies."""
        condition_code = request.data.get('condition_code')
        patient_ids = request.data.get('patient_ids')
        
        # Permission check: only researchers and admins
        if request.user.role not in ['researcher', 'admin', 'superadmin']:
            return Response(
                {'error': 'Insufficient permissions'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        try:
            fhir_service = AdvancedFHIRIntegrationService()
            result = fhir_service.create_rare_disease_research_bundle(condition_code, patient_ids)
            
            return Response(result)
            
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class EnhancedTelemedicineViewSet(viewsets.ViewSet):
    """
    Enhanced telemedicine with intelligent preparation and monitoring.
    Builds on your existing FHIREncounter model.
    """
    permission_classes = [IsAuthenticated, IsApprovedUser]
    
    @swagger_auto_schema(
        method='post',
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'patient_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'provider_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'start_time': openapi.Schema(type=openapi.TYPE_STRING, format='datetime'),
                'duration': openapi.Schema(type=openapi.TYPE_INTEGER, default=30),
                'platform': openapi.Schema(type=openapi.TYPE_STRING, enum=['zoom', 'teams', 'webex', 'custom']),
                'reason_display': openapi.Schema(type=openapi.TYPE_STRING),
                'priority': openapi.Schema(type=openapi.TYPE_STRING, enum=['routine', 'urgent', 'stat'])
            }
        ),
        responses={200: 'Telemedicine appointment scheduled successfully'}
    )
    @action(detail=False, methods=['post'])
    def schedule_intelligent_appointment(self, request):
        """Schedule telemedicine appointment with intelligent preparation."""
        appointment_data = request.data
        patient_id = appointment_data.get('patient_id')
        provider_id = appointment_data.get('provider_id')
        
        # Permission checks
        if request.user.role == 'patient' and patient_id != request.user.id:
            return Response(
                {'error': 'Unauthorized access'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        if request.user.role == 'provider' and provider_id != request.user.id:
            return Response(
                {'error': 'Unauthorized access'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        try:
            result = EnhancedTelemedicineService.schedule_intelligent_appointment(
                patient_id, provider_id, appointment_data
            )
            
            return Response(result)
            
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @swagger_auto_schema(
        method='post',
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'encounter_id': openapi.Schema(type=openapi.TYPE_INTEGER)
            }
        ),
        responses={200: 'Pre-visit data collection completed'}
    )
    @action(detail=False, methods=['post'])
    def prepare_pre_visit_data(self, request):
        """Collect and prepare patient data before telemedicine visit."""
        encounter_id = request.data.get('encounter_id')
        
        try:
            result = EnhancedTelemedicineService.prepare_pre_visit_data_collection(encounter_id)
            return Response(result)
            
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @swagger_auto_schema(
        method='post',
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'encounter_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'vitals_data': openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'blood_pressure_systolic': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'value': openapi.Schema(type=openapi.TYPE_NUMBER),
                                'unit': openapi.Schema(type=openapi.TYPE_STRING)
                            }
                        ),
                        'heart_rate': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'value': openapi.Schema(type=openapi.TYPE_NUMBER),
                                'unit': openapi.Schema(type=openapi.TYPE_STRING)
                            }
                        )
                    }
                )
            }
        ),
        responses={200: 'Session vitals captured successfully'}
    )
    @action(detail=False, methods=['post'])
    def capture_session_vitals(self, request):
        """Capture vital signs during telemedicine session."""
        encounter_id = request.data.get('encounter_id')
        vitals_data = request.data.get('vitals_data', {})
        
        try:
            result = EnhancedTelemedicineService.capture_session_vitals(encounter_id, vitals_data)
            return Response(result)
            
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @swagger_auto_schema(
        method='get',
        manual_parameters=[
            openapi.Parameter('provider_id', openapi.IN_QUERY, type=openapi.TYPE_INTEGER, required=False)
        ],
        responses={200: 'Provider dashboard data retrieved successfully'}
    )
    @action(detail=False, methods=['get'])
    def get_provider_dashboard(self, request):
        """Get comprehensive dashboard data for healthcare providers."""
        provider_id = request.query_params.get('provider_id', request.user.id)
        
        # Permission check
        if request.user.role == 'provider' and int(provider_id) != request.user.id:
            return Response(
                {'error': 'Unauthorized access'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        try:
            result = EnhancedTelemedicineService.get_provider_dashboard_data(int(provider_id))
            return Response(result)
            
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class EnhancedResearchViewSet(viewsets.ViewSet):
    """
    Enhanced research and clinical trials management.
    Builds on your existing consent and researcher models.
    """
    permission_classes = [IsAuthenticated, IsApprovedUser]
    
    @swagger_auto_schema(
        method='post',
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'title': openapi.Schema(type=openapi.TYPE_STRING),
                'description': openapi.Schema(type=openapi.TYPE_STRING),
                'study_type': openapi.Schema(type=openapi.TYPE_STRING, enum=['observational', 'interventional']),
                'target_conditions': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Schema(type=openapi.TYPE_STRING)),
                'data_requirements': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Schema(type=openapi.TYPE_STRING)),
                'duration_months': openapi.Schema(type=openapi.TYPE_INTEGER),
                'max_participants': openapi.Schema(type=openapi.TYPE_INTEGER)
            }
        ),
        responses={200: 'Research study created successfully'}
    )
    @action(detail=False, methods=['post'])
    def create_research_study(self, request):
        """Create new research study with proper consent management."""
        # Permission check: only researchers can create studies
        if request.user.role != 'researcher':
            return Response(
                {'error': 'Only researchers can create studies'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        try:
            result = ResearchClinicalTrialsService.create_research_study(
                request.user.id, request.data
            )
            
            return Response(result)
            
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @swagger_auto_schema(
        method='post',
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'study_id': openapi.Schema(type=openapi.TYPE_STRING),
                'patient_id': openapi.Schema(type=openapi.TYPE_INTEGER)
            }
        ),
        responses={200: 'Patient invitation sent successfully'}
    )
    @action(detail=False, methods=['post'])
    def invite_patient_to_study(self, request):
        """Invite patient to participate in research study."""
        study_id = request.data.get('study_id')
        patient_id = request.data.get('patient_id')
        
        # Permission check: only researchers
        if request.user.role != 'researcher':
            return Response(
                {'error': 'Only researchers can invite patients'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        try:
            result = ResearchClinicalTrialsService.invite_patient_to_study(
                study_id, patient_id, request.user.id
            )
            
            return Response(result)
            
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @swagger_auto_schema(
        method='get',
        manual_parameters=[
            openapi.Parameter('patient_id', openapi.IN_QUERY, type=openapi.TYPE_INTEGER, required=False)
        ],
        responses={200: 'Patient research dashboard retrieved successfully'}
    )
    @action(detail=False, methods=['get'])
    def get_patient_research_dashboard(self, request):
        """Get research participation dashboard for patients."""
        patient_id = request.query_params.get('patient_id', request.user.id)
        
        # Permission check
        if request.user.role == 'patient' and int(patient_id) != request.user.id:
            return Response(
                {'error': 'Unauthorized access'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        try:
            result = ResearchClinicalTrialsService.get_patient_research_dashboard(int(patient_id))
            return Response(result)
            
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @swagger_auto_schema(
        method='post',
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'study_id': openapi.Schema(type=openapi.TYPE_STRING),
                'patient_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                'collection_type': openapi.Schema(type=openapi.TYPE_STRING, enum=['routine', 'baseline', 'follow_up'])
            }
        ),
        responses={200: 'Research data collected successfully'}
    )
    @action(detail=False, methods=['post'])
    def collect_research_data(self, request):
        """Collect and aggregate research data for study participant."""
        study_id = request.data.get('study_id')
        patient_id = request.data.get('patient_id')
        collection_type = request.data.get('collection_type', 'routine')
        
        # Permission check: researchers and providers can collect data
        if request.user.role not in ['researcher', 'provider', 'admin']:
            return Response(
                {'error': 'Insufficient permissions'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        try:
            result = ResearchClinicalTrialsService.collect_research_data(
                study_id, patient_id, collection_type
            )
            
            return Response(result)
            
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )