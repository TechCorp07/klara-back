from rest_framework import viewsets, permissions, filters, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from django.utils import timezone
from django.db.models import Q, Count
from django.http import Http404
from django.contrib.auth import get_user_model

from .models import (
    MedicalRecord, Medication, MedicationIntake, Allergy, Condition, ConditionFlare,
    Symptom, Immunization, LabTest, LabResult, VitalSign, Treatment, FamilyHistory,
    HealthDataConsent, HealthDataAuditLog, EHRIntegration, WearableIntegration,
    RareConditionRegistry, ReferralNetwork
)
from .serializers import (
    MedicalRecordSerializer, MedicalRecordDetailSerializer, MedicationSerializer,
    MedicationIntakeSerializer, AllergySerializer, ConditionSerializer, ConditionFlareSerializer,
    SymptomSerializer, ImmunizationSerializer, LabTestSerializer, LabResultSerializer,
    VitalSignSerializer, TreatmentSerializer, FamilyHistorySerializer,
    HealthDataConsentSerializer, HealthDataAuditLogSerializer, EHRIntegrationSerializer,
    WearableIntegrationSerializer, RareConditionRegistrySerializer, ReferralNetworkSerializer
)
from .permissions import (
    IsApprovedUser, IsPatientOrProvider, IsProviderOnly,
    IsPatientOrProviderForRecord, HasHealthDataConsent,
    CanViewAuditLogs, IsProviderForReferral
)

from users.permissions import IsApprovedUser as UserApprovalCheck

User = get_user_model()

class BaseHealthcareViewSet(viewsets.ModelViewSet):
    """Base ViewSet for healthcare models with audit logging."""
    permission_classes = [permissions.IsAuthenticated, IsApprovedUser]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter, filters.SearchFilter]
    
    def get_serializer_context(self):
        """Add user role to the serializer context."""
        context = super().get_serializer_context()
        
        # Check for Swagger schema generation
        if getattr(self, 'swagger_fake_view', False):
            # Return minimal context for schema generation
            return context
            
        # Add user role if user is authenticated
        user = self.request.user
        if user and hasattr(user, 'role'):
            context['user_role'] = user.role
        else:
            context['user_role'] = None
            
        return context
        
    def log_access(self, obj, action_type, details=''):
        """Log access to health data for HIPAA compliance."""
        try:
            # Determine patient ID
            if hasattr(obj, 'patient_id'):
                patient_id = obj.patient_id
            elif hasattr(obj, 'medical_record') and hasattr(obj.medical_record, 'patient_id'):
                patient_id = obj.medical_record.patient_id
            elif hasattr(obj, 'lab_test') and hasattr(obj.lab_test, 'medical_record'):
                patient_id = obj.lab_test.medical_record.patient_id
            else:
                patient_id = 'unknown'
            
            # Create audit log
            HealthDataAuditLog.objects.create(
                user=self.request.user,
                action=action_type,
                resource_type=obj.__class__.__name__,
                resource_id=str(obj.id),
                patient_id=str(patient_id),
                ip_address=self._get_client_ip(),
                user_agent=self.request.META.get('HTTP_USER_AGENT', ''),
                access_reason=self.request.query_params.get('reason', ''),
                details=details
            )
        except Exception as e:
            # Log error but don't block the request
            import logging
            logger = logging.getLogger('django')
            logger.error(f"Error logging health data access: {str(e)}")
    
    def _get_client_ip(self):
        """Get client IP safely accounting for proxies."""
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = self.request.META.get('REMOTE_ADDR', '')
        return ip
    
    def retrieve(self, request, *args, **kwargs):
        """Override retrieve to log access."""
        response = super().retrieve(request, *args, **kwargs)
        self.log_access(self.get_object(), 'view')
        return response
    
    def update(self, request, *args, **kwargs):
        """Override update to log access."""
        response = super().update(request, *args, **kwargs)
        self.log_access(self.get_object(), 'update')
        return response
    
    def destroy(self, request, *args, **kwargs):
        """Override destroy to log access."""
        obj = self.get_object()
        self.log_access(obj, 'delete')
        return super().destroy(request, *args, **kwargs)


class MedicalRecordViewSet(BaseHealthcareViewSet):
    """ViewSet for medical records."""
    queryset = MedicalRecord.objects.all()
    serializer_class = MedicalRecordSerializer
    permission_classes = [permissions.IsAuthenticated, IsApprovedUser, IsPatientOrProviderForRecord]
    filterset_fields = ['patient', 'primary_physician', 'has_rare_condition']
    search_fields = ['patient__username', 'patient__email', 'patient__first_name', 'patient__last_name']
    ordering_fields = ['created_at', 'updated_at']
    
    def get_serializer_class(self):
        """Use detailed serializer for retrieve actions."""
        if self.action == 'retrieve':
            return MedicalRecordDetailSerializer
        return MedicalRecordSerializer
    
    def get_queryset(self):
        """Filter records based on user role."""
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        queryset = super().get_queryset()
        
        # Filter queryset based on role
        if user.role == 'patient':
            return queryset.filter(patient=user)
        elif user.role == 'provider':
            return queryset.filter(
                Q(primary_physician=user) | 
                Q(patient__in=user.primary_patients.all())
            )
        elif user.role == 'caregiver' and hasattr(user, 'caregiver_profile'):
            # Get patients this caregiver is authorized for
            authorized_patients = user.caregiver_patients.all()
            return queryset.filter(patient__in=authorized_patients)
        elif user.role == 'researcher' and hasattr(user, 'researcher_profile'):
            if user.researcher_profile.is_verified:
                # Researchers can only see records with research consent
                return queryset.filter(research_participation_consent=True)
            return MedicalRecord.objects.none()
        elif user.role == 'pharmco':
            # Pharma companies can see records with medication adherence consent
            return queryset.filter(patient__medication_adherence_monitoring_consent=True)
        elif user.role == 'compliance' and hasattr(user, 'compliance_profile'):
            if user.compliance_profile.can_view_phi:
                return queryset
            return MedicalRecord.objects.none()
        
        # Admin or staff can see all
        if user.is_staff or user.role == 'admin':
            return queryset
            
        return MedicalRecord.objects.none()
    
    @action(detail=True, methods=['get'])
    def summary(self, request, pk=None):
        """Get a summary of patient health data."""
        record = self.get_object()
        
        # Log the summary access
        self.log_access(record, 'view', 'Summary view of medical record')
        
        # Gather counts of different records
        conditions_count = record.conditions.count()
        active_conditions = record.conditions.filter(status='active').count()
        medications_count = record.medications.filter(active=True).count()
        allergies_count = record.allergies.count()
        
        # Recent data
        recent_labs = LabTestSerializer(
            record.lab_tests.order_by('-ordered_date')[:5], 
            many=True, 
            context=self.get_serializer_context()
        ).data
        
        recent_vitals = VitalSignSerializer(
            record.vital_signs.order_by('-measured_at')[:5], 
            many=True, 
            context=self.get_serializer_context()
        ).data
        
        # Stats for rare conditions
        rare_conditions = record.conditions.filter(is_rare_condition=True)
        rare_condition_data = ConditionSerializer(
            rare_conditions, 
            many=True, 
            context=self.get_serializer_context()
        ).data
        
        return Response({
            'patient_name': f"{record.patient.first_name} {record.patient.last_name}",
            'date_of_birth': record.date_of_birth,
            'has_rare_condition': record.has_rare_condition,
            'counts': {
                'conditions': conditions_count,
                'active_conditions': active_conditions,
                'medications': medications_count,
                'allergies': allergies_count,
                'lab_tests': record.lab_tests.count(),
                'immunizations': record.immunizations.count(),
            },
            'recent_data': {
                'lab_tests': recent_labs,
                'vitals': recent_vitals,
            },
            'rare_conditions': rare_condition_data,
        })


class MedicationViewSet(BaseHealthcareViewSet):
    """ViewSet for medications."""
    queryset = Medication.objects.all()
    serializer_class = MedicationSerializer
    permission_classes = [permissions.IsAuthenticated, IsApprovedUser, HasHealthDataConsent]
    filterset_fields = ['medical_record', 'active', 'for_rare_condition', 'is_specialty_medication']
    search_fields = ['name', 'reason']
    ordering_fields = ['start_date', 'end_date', 'created_at']
    
    def get_queryset(self):
        """Filter medications based on user role and permissions."""
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        queryset = super().get_queryset()
        
        # Filter queryset based on role
        if user.role == 'patient':
            return queryset.filter(medical_record__patient=user)
        elif user.role == 'provider':
            return queryset.filter(
                Q(prescriber=user) | 
                Q(medical_record__primary_physician=user) |
                Q(medical_record__patient__in=user.primary_patients.all())
            )
        elif user.role == 'caregiver' and hasattr(user, 'caregiver_profile'):
            # Get patients this caregiver is authorized for
            authorized_patients = user.caregiver_patients.all()
            return queryset.filter(medical_record__patient__in=authorized_patients)
        elif user.role == 'pharmco':
            # Pharma companies can see medications for patients with consent
            return queryset.filter(medical_record__patient__medication_adherence_monitoring_consent=True)
        
        # Admin or staff can see all
        if user.is_staff or user.role == 'admin':
            return queryset
            
        return Medication.objects.none()
    
    @action(detail=True, methods=['get'])
    def adherence(self, request, pk=None):
        """Get medication adherence data."""
        medication = self.get_object()
        
        # Log the adherence data access
        self.log_access(medication, 'view', 'Medication adherence data')
        
        # Get intake records
        intakes = medication.intakes.all().order_by('-taken_at')
        
        # Calculate adherence rate
        total_intakes = intakes.count()
        skipped_intakes = intakes.filter(skipped=True).count()
        
        if total_intakes > 0:
            adherence_rate = ((total_intakes - skipped_intakes) / total_intakes) * 100
        else:
            adherence_rate = 0
        
        # Format data for response
        intake_data = MedicationIntakeSerializer(
            intakes, 
            many=True, 
            context=self.get_serializer_context()
        ).data
        
        return Response({
            'medication': MedicationSerializer(medication, context=self.get_serializer_context()).data,
            'adherence_stats': {
                'total_intakes': total_intakes,
                'taken_intakes': total_intakes - skipped_intakes,
                'skipped_intakes': skipped_intakes,
                'adherence_rate': round(adherence_rate, 2),
            },
            'intake_history': intake_data,
        })


class MedicationIntakeViewSet(BaseHealthcareViewSet):
    """ViewSet for medication intake records."""
    queryset = MedicationIntake.objects.all()
    serializer_class = MedicationIntakeSerializer
    permission_classes = [permissions.IsAuthenticated, IsApprovedUser, HasHealthDataConsent]
    filterset_fields = ['medication', 'skipped', 'recorded_via']
    ordering_fields = ['taken_at', 'created_at']
    
    def get_queryset(self):
        """Filter medication intakes based on user role and permissions."""
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        queryset = super().get_queryset()
        
        # Filter queryset based on role
        if user.role == 'patient':
            return queryset.filter(medication__medical_record__patient=user)
        elif user.role == 'provider':
            return queryset.filter(
                Q(medication__prescriber=user) | 
                Q(medication__medical_record__primary_physician=user) |
                Q(medication__medical_record__patient__in=user.primary_patients.all())
            )
        elif user.role == 'caregiver' and hasattr(user, 'caregiver_profile'):
            # Get patients this caregiver is authorized for
            authorized_patients = user.caregiver_patients.all()
            return queryset.filter(medication__medical_record__patient__in=authorized_patients)
        elif user.role == 'pharmco':
            # Pharma companies can see medication intakes for patients with consent
            return queryset.filter(
                medication__medical_record__patient__medication_adherence_monitoring_consent=True
            )
        
        # Admin or staff can see all
        if user.is_staff or user.role == 'admin':
            return queryset
            
        return MedicationIntake.objects.none()
    
    def perform_create(self, serializer):
        """Set the recorded_by field to the current user."""
        serializer.save(recorded_by=self.request.user)

class AllergyViewSet(BaseHealthcareViewSet):
    """ViewSet for allergies."""
    queryset = Allergy.objects.all()
    serializer_class = AllergySerializer
    permission_classes = [permissions.IsAuthenticated, IsApprovedUser, HasHealthDataConsent]
    filterset_fields = ['medical_record', 'severity', 'allergy_type']
    search_fields = ['agent', 'reaction']
    ordering_fields = ['created_at', 'severity']
    
    def get_queryset(self):
        """Filter allergies based on user role and permissions."""
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        queryset = super().get_queryset()
        
        # Filter queryset based on role
        if user.role == 'patient':
            return queryset.filter(medical_record__patient=user)
        elif user.role == 'provider':
            return queryset.filter(
                Q(medical_record__primary_physician=user) |
                Q(medical_record__patient__in=user.primary_patients.all())
            )
        elif user.role == 'caregiver' and hasattr(user, 'caregiver_profile'):
            # Get patients this caregiver is authorized for
            authorized_patients = user.caregiver_patients.all()
            return queryset.filter(medical_record__patient__in=authorized_patients)
        
        # Admin or staff can see all
        if user.is_staff or user.role == 'admin':
            return queryset
            
        return Allergy.objects.none()
    
    def get_serializer_context(self):
        """Add user role to the serializer context."""
        context = super().get_serializer_context()
        
        # Check for Swagger schema generation
        if getattr(self, 'swagger_fake_view', False):
            # Return minimal context for schema generation
            return context
            
        # Add user role if user is authenticated
        user = self.request.user
        if user and hasattr(user, 'role'):
            context['user_role'] = user.role
        else:
            context['user_role'] = None
            
        return context


class ConditionViewSet(BaseHealthcareViewSet):
    """ViewSet for medical conditions."""
    queryset = Condition.objects.all()
    serializer_class = ConditionSerializer
    permission_classes = [permissions.IsAuthenticated, IsApprovedUser, HasHealthDataConsent]
    filterset_fields = ['medical_record', 'status', 'category', 'is_rare_condition', 'is_primary']
    search_fields = ['name', 'notes', 'icd10_code']
    ordering_fields = ['diagnosed_date', 'created_at']
    
    def get_queryset(self):
        """Filter conditions based on user role and permissions."""
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        queryset = super().get_queryset()
        
        # Filter queryset based on role
        if user.role == 'patient':
            return queryset.filter(medical_record__patient=user)
        elif user.role == 'provider':
            return queryset.filter(
                Q(medical_record__primary_physician=user) |
                Q(medical_record__patient__in=user.primary_patients.all())
            )
        elif user.role == 'caregiver' and hasattr(user, 'caregiver_profile'):
            # Get patients this caregiver is authorized for
            authorized_patients = user.caregiver_patients.all()
            return queryset.filter(medical_record__patient__in=authorized_patients)
        elif user.role == 'researcher' and hasattr(user, 'researcher_profile'):
            if user.researcher_profile.is_verified:
                # Researchers can only see conditions with research consent
                return queryset.filter(medical_record__research_participation_consent=True)
            return Condition.objects.none()
        
        # Admin or staff can see all
        if user.is_staff or user.role == 'admin':
            return queryset
            
        return Condition.objects.none()
    
    @action(detail=True, methods=['get'])
    def timeline(self, request, pk=None):
        """Get condition timeline with flares, treatments, and lab tests."""
        condition = self.get_object()
        
        # Log the timeline access
        self.log_access(condition, 'view', 'Condition timeline')
        
        # Get related data
        flares = ConditionFlareSerializer(
            condition.flares.all().order_by('-onset_date'),
            many=True,
            context=self.get_serializer_context()
        ).data
        
        symptoms = SymptomSerializer(
            condition.symptoms.all().order_by('-severity'),
            many=True,
            context=self.get_serializer_context()
        ).data
        
        treatments = TreatmentSerializer(
            condition.condition_treatments.all().order_by('-start_date'),
            many=True,
            context=self.get_serializer_context()
        ).data
        
        lab_tests = LabTestSerializer(
            condition.related_lab_tests.all().order_by('-ordered_date'),
            many=True,
            context=self.get_serializer_context()
        ).data
        
        # Build timeline events
        timeline_events = []
        
        # Add diagnosis event
        if condition.diagnosed_date:
            timeline_events.append({
                'date': condition.diagnosed_date,
                'event_type': 'diagnosis',
                'description': f"Diagnosed with {condition.name}",
                'details': {
                    'diagnosing_provider': condition.diagnosing_provider,
                    'notes': condition.notes
                }
            })
        
        # Add flare events
        for flare in condition.flares.all():
            timeline_events.append({
                'date': flare.onset_date,
                'event_type': 'flare_onset',
                'description': f"Condition flare (Severity: {flare.severity}/10)",
                'details': {
                    'symptoms': flare.symptoms,
                    'hospitalized': flare.hospitalized,
                    'treatment': flare.treatment
                }
            })
            
            if flare.resolved_date:
                timeline_events.append({
                    'date': flare.resolved_date,
                    'event_type': 'flare_resolution',
                    'description': f"Flare resolved",
                    'details': {
                        'duration_days': (flare.resolved_date - flare.onset_date).days,
                        'notes': flare.notes
                    }
                })
        
        # Add treatment events
        for treatment in condition.condition_treatments.all():
            timeline_events.append({
                'date': treatment.start_date,
                'event_type': 'treatment_start',
                'description': f"Started {treatment.name} ({treatment.treatment_type})",
                'details': {
                    'provider': treatment.provider.get_full_name() if treatment.provider else None,
                    'location': treatment.location,
                    'reason': treatment.reason
                }
            })
            
            if treatment.end_date:
                timeline_events.append({
                    'date': treatment.end_date,
                    'event_type': 'treatment_end',
                    'description': f"Completed {treatment.name}",
                    'details': {
                        'outcome': treatment.outcome,
                        'complications': treatment.complications
                    }
                })
        
        # Add lab test events
        for lab_test in condition.related_lab_tests.all():
            timeline_events.append({
                'date': lab_test.ordered_date,
                'event_type': 'lab_test_ordered',
                'description': f"Lab test ordered: {lab_test.name}",
                'details': {
                    'ordered_by': lab_test.ordered_by.get_full_name() if lab_test.ordered_by else None,
                    'status': lab_test.get_status_display(),
                    'notes': lab_test.notes
                }
            })
            
            if lab_test.completed_date:
                abnormal_results = lab_test.results.filter(is_abnormal=True).count()
                timeline_events.append({
                    'date': lab_test.completed_date,
                    'event_type': 'lab_test_completed',
                    'description': f"Lab test completed: {lab_test.name}",
                    'details': {
                        'abnormal_results': abnormal_results,
                        'total_results': lab_test.results.count()
                    }
                })
        
        # Sort timeline by date
        sorted_timeline = sorted(timeline_events, key=lambda x: x['date'], reverse=True)
        
        return Response({
            'condition': ConditionSerializer(condition, context=self.get_serializer_context()).data,
            'timeline': sorted_timeline,
            'flares': flares,
            'symptoms': symptoms,
            'treatments': treatments,
            'lab_tests': lab_tests
        })


class ConditionFlareViewSet(BaseHealthcareViewSet):
    """ViewSet for condition flares."""
    queryset = ConditionFlare.objects.all()
    serializer_class = ConditionFlareSerializer
    permission_classes = [permissions.IsAuthenticated, IsApprovedUser, HasHealthDataConsent]
    filterset_fields = ['condition', 'hospitalized', 'severity']
    ordering_fields = ['onset_date', 'created_at']
    
    def get_queryset(self):
        """Filter condition flares based on user role and permissions."""
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        queryset = super().get_queryset()
        
        # Filter queryset based on role
        if user.role == 'patient':
            return queryset.filter(condition__medical_record__patient=user)
        elif user.role == 'provider':
            return queryset.filter(
                Q(condition__medical_record__primary_physician=user) |
                Q(condition__medical_record__patient__in=user.primary_patients.all())
            )
        elif user.role == 'caregiver' and hasattr(user, 'caregiver_profile'):
            # Get patients this caregiver is authorized for
            authorized_patients = user.caregiver_patients.all()
            return queryset.filter(condition__medical_record__patient__in=authorized_patients)
        elif user.role == 'researcher' and hasattr(user, 'researcher_profile'):
            if user.researcher_profile.is_verified:
                # Researchers can only see flares with research consent
                return queryset.filter(condition__medical_record__research_participation_consent=True)
            return ConditionFlare.objects.none()
        
        # Admin or staff can see all
        if user.is_staff or user.role == 'admin':
            return queryset
            
        return ConditionFlare.objects.none()
    
    def perform_create(self, serializer):
        """Set the recorded_by field to the current user."""
        serializer.save(recorded_by=self.request.user)


class SymptomViewSet(BaseHealthcareViewSet):
    """ViewSet for symptoms."""
    queryset = Symptom.objects.all()
    serializer_class = SymptomSerializer
    permission_classes = [permissions.IsAuthenticated, IsApprovedUser, HasHealthDataConsent]
    filterset_fields = ['condition', 'is_active', 'severity']
    search_fields = ['name', 'description']
    ordering_fields = ['severity', 'first_observed', 'created_at']
    
    def get_queryset(self):
        """Filter symptoms based on user role and permissions."""
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        queryset = super().get_queryset()
        
        # Filter queryset based on role
        if user.role == 'patient':
            return queryset.filter(condition__medical_record__patient=user)
        elif user.role == 'provider':
            return queryset.filter(
                Q(condition__medical_record__primary_physician=user) |
                Q(condition__medical_record__patient__in=user.primary_patients.all())
            )
        elif user.role == 'caregiver' and hasattr(user, 'caregiver_profile'):
            # Get patients this caregiver is authorized for
            authorized_patients = user.caregiver_patients.all()
            return queryset.filter(condition__medical_record__patient__in=authorized_patients)
        elif user.role == 'researcher' and hasattr(user, 'researcher_profile'):
            if user.researcher_profile.is_verified:
                # Researchers can only see symptoms with research consent
                return queryset.filter(condition__medical_record__research_participation_consent=True)
            return Symptom.objects.none()
        
        # Admin or staff can see all
        if user.is_staff or user.role == 'admin':
            return queryset
            
        return Symptom.objects.none()
    
    @action(detail=False, methods=['get'])
    def by_condition(self, request):
        """Get symptoms grouped by condition."""
        condition_id = request.query_params.get('condition_id')
        if not condition_id:
            return Response(
                {"error": "condition_id parameter is required"},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        try:
            condition = Condition.objects.get(id=condition_id)
            
            # Check permissions
            self.check_object_permissions(request, condition)
            
            # Log the access
            self.log_access(condition, 'view', 'Symptoms by condition')
            
            # Get symptoms for this condition
            symptoms = condition.symptoms.all().order_by('-severity')
            
            # Serialize the data
            symptom_data = SymptomSerializer(
                symptoms,
                many=True,
                context=self.get_serializer_context()
            ).data
            
            return Response({
                'condition': ConditionSerializer(condition, context=self.get_serializer_context()).data,
                'symptoms': symptom_data,
                'total_symptoms': symptoms.count(),
                'active_symptoms': symptoms.filter(is_active=True).count(),
            })
        except Condition.DoesNotExist:
            raise Http404("Condition not found")


class ImmunizationViewSet(BaseHealthcareViewSet):
    """ViewSet for immunizations."""
    queryset = Immunization.objects.all()
    serializer_class = ImmunizationSerializer
    permission_classes = [permissions.IsAuthenticated, IsApprovedUser, HasHealthDataConsent]
    search_fields = ['vaccine', 'administered_by', 'lot_number']
    ordering_fields = ['date_administered', 'created_at']
    
    def get_filterset_fields(self):
        """Dynamic filterset fields based on context."""
        # During schema generation, exclude the problematic 'vaccine' field
        if getattr(self, 'swagger_fake_view', False):
            return ['medical_record']
        # For normal operation, include all filter fields
        return ['medical_record', 'vaccine']
    
    def get_queryset(self):
        """Filter immunizations based on user role and permissions."""
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        queryset = super().get_queryset()
        
        # Filter queryset based on role
        if user.role == 'patient':
            return queryset.filter(medical_record__patient=user)
        elif user.role == 'provider':
            return queryset.filter(
                Q(medical_record__primary_physician=user) |
                Q(medical_record__patient__in=user.primary_patients.all())
            )
        elif user.role == 'caregiver' and hasattr(user, 'caregiver_profile'):
            # Get patients this caregiver is authorized for
            authorized_patients = user.caregiver_patients.all()
            return queryset.filter(medical_record__patient__in=authorized_patients)
        
        # Admin or staff can see all
        if user.is_staff or user.role == 'admin':
            return queryset
            
        return Immunization.objects.none()

class LabTestViewSet(BaseHealthcareViewSet):
    """ViewSet for lab tests."""
    queryset = LabTest.objects.all()
    serializer_class = LabTestSerializer
    permission_classes = [permissions.IsAuthenticated, IsApprovedUser, HasHealthDataConsent]
    filterset_fields = ['medical_record', 'status', 'for_rare_condition_monitoring', 'related_condition']
    search_fields = ['name', 'notes', 'lab_location']
    ordering_fields = ['ordered_date', 'completed_date', 'created_at']
    
    def get_queryset(self):
        """Filter lab tests based on user role and permissions."""
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        queryset = super().get_queryset()
        
        # Filter queryset based on role
        if user.role == 'patient':
            return queryset.filter(medical_record__patient=user)
        elif user.role == 'provider':
            return queryset.filter(
                Q(ordered_by=user) |
                Q(medical_record__primary_physician=user) |
                Q(medical_record__patient__in=user.primary_patients.all())
            )
        elif user.role == 'caregiver' and hasattr(user, 'caregiver_profile'):
            # Get patients this caregiver is authorized for
            authorized_patients = user.caregiver_patients.all()
            return queryset.filter(medical_record__patient__in=authorized_patients)
        elif user.role == 'researcher' and hasattr(user, 'researcher_profile'):
            if user.researcher_profile.is_verified:
                # Researchers can only see lab tests with research consent
                return queryset.filter(medical_record__research_participation_consent=True)
            return LabTest.objects.none()
        
        # Admin or staff can see all
        if user.is_staff or user.role == 'admin':
            return queryset
            
        return LabTest.objects.none()
    
    @action(detail=True, methods=['post'])
    def update_status(self, request, pk=None):
        """Update the status of a lab test."""
        lab_test = self.get_object()
        new_status = request.data.get('status')
        
        # Validate status
        if new_status not in dict(LabTest.Status.choices).keys():
            return Response(
                {"error": f"Invalid status. Must be one of: {', '.join(dict(LabTest.Status.choices).keys())}"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Update status and completed date if applicable
        lab_test.status = new_status
        if new_status == 'completed' and not lab_test.completed_date:
            lab_test.completed_date = timezone.now().date()
        
        lab_test.save()
        
        # Log the update
        self.log_access(lab_test, 'update', f"Status updated to {new_status}")
        
        return Response(LabTestSerializer(lab_test, context=self.get_serializer_context()).data)


class LabResultViewSet(BaseHealthcareViewSet):
    """ViewSet for lab results."""
    queryset = LabResult.objects.all()
    serializer_class = LabResultSerializer
    permission_classes = [permissions.IsAuthenticated, IsApprovedUser, HasHealthDataConsent]
    filterset_fields = ['lab_test', 'is_abnormal']
    search_fields = ['test_name', 'value', 'notes']
    ordering_fields = ['created_at', 'result_date']
    
    def get_queryset(self):
        """Filter lab results based on user role and permissions."""
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        queryset = super().get_queryset()
        
        # Filter queryset based on role
        if user.role == 'patient':
            return queryset.filter(lab_test__medical_record__patient=user)
        elif user.role == 'provider':
            return queryset.filter(
                Q(lab_test__ordered_by=user) |
                Q(interpreted_by=user) |
                Q(lab_test__medical_record__primary_physician=user) |
                Q(lab_test__medical_record__patient__in=user.primary_patients.all())
            )
        elif user.role == 'caregiver' and hasattr(user, 'caregiver_profile'):
            # Get patients this caregiver is authorized for
            authorized_patients = user.caregiver_patients.all()
            return queryset.filter(lab_test__medical_record__patient__in=authorized_patients)
        elif user.role == 'researcher' and hasattr(user, 'researcher_profile'):
            if user.researcher_profile.is_verified:
                # Researchers can only see lab results with research consent
                return queryset.filter(lab_test__medical_record__research_participation_consent=True)
            return LabResult.objects.none()
        
        # Admin or staff can see all
        if user.is_staff or user.role == 'admin':
            return queryset
            
        return LabResult.objects.none()
    
    @action(detail=True, methods=['post'])
    def add_interpretation(self, request, pk=None):
        """Add an interpretation to a lab result."""
        lab_result = self.get_object()
        interpretation = request.data.get('interpretation')
        
        if not interpretation:
            return Response(
                {"error": "Interpretation is required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Update interpretation
        lab_result.interpretation = interpretation
        lab_result.interpreted_by = request.user
        lab_result.save()
        
        # Log the update
        self.log_access(lab_result, 'update', "Added interpretation")
        
        return Response(LabResultSerializer(lab_result, context=self.get_serializer_context()).data)


class VitalSignViewSet(BaseHealthcareViewSet):
    """ViewSet for vital signs."""
    queryset = VitalSign.objects.all()
    serializer_class = VitalSignSerializer
    permission_classes = [permissions.IsAuthenticated, IsApprovedUser, HasHealthDataConsent]
    filterset_fields = ['medical_record', 'measurement_type', 'source', 'is_abnormal']
    search_fields = ['notes', 'context']
    ordering_fields = ['measured_at', 'created_at']
    
    def get_queryset(self):
        """Filter vital signs based on user role and permissions."""
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        queryset = super().get_queryset()
        
        # Filter queryset based on role
        if user.role == 'patient':
            return queryset.filter(medical_record__patient=user)
        elif user.role == 'provider':
            return queryset.filter(
                Q(medical_record__primary_physician=user) |
                Q(medical_record__patient__in=user.primary_patients.all())
            )
        elif user.role == 'caregiver' and hasattr(user, 'caregiver_profile'):
            # Get patients this caregiver is authorized for
            authorized_patients = user.caregiver_patients.all()
            return queryset.filter(medical_record__patient__in=authorized_patients)
        elif user.role == 'researcher' and hasattr(user, 'researcher_profile'):
            if user.researcher_profile.is_verified:
                # Researchers can only see vitals with research consent
                return queryset.filter(medical_record__research_participation_consent=True)
            return VitalSign.objects.none()
        
        # Admin or staff can see all
        if user.is_staff or user.role == 'admin':
            return queryset
            
        return VitalSign.objects.none()
    
    @action(detail=False, methods=['get'])
    def recent(self, request):
        """Get recent vital signs for a patient."""
        medical_record_id = request.query_params.get('medical_record_id')
        measurement_type = request.query_params.get('measurement_type')
        limit = int(request.query_params.get('limit', 10))
        
        if not medical_record_id:
            return Response(
                {"error": "medical_record_id parameter is required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Build queryset
        queryset = self.get_queryset().filter(medical_record_id=medical_record_id)
        if measurement_type:
            queryset = queryset.filter(measurement_type=measurement_type)
        
        # Get recent vitals
        recent_vitals = queryset.order_by('-measured_at')[:limit]
        
        # Serialize the data
        vitals_data = VitalSignSerializer(
            recent_vitals,
            many=True,
            context=self.get_serializer_context()
        ).data
        
        # Log access
        try:
            medical_record = MedicalRecord.objects.get(id=medical_record_id)
            self.log_access(medical_record, 'view', f"Recent vital signs")
        except MedicalRecord.DoesNotExist:
            pass
        
        return Response({
            'vitals': vitals_data,
            'count': recent_vitals.count(),
        })
    
    @action(detail=False, methods=['get'])
    def trends(self, request):
        """Get vital sign trends for a patient."""
        medical_record_id = request.query_params.get('medical_record_id')
        measurement_type = request.query_params.get('measurement_type')
        days = int(request.query_params.get('days', 30))
        
        if not medical_record_id or not measurement_type:
            return Response(
                {"error": "medical_record_id and measurement_type parameters are required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Calculate date range
        end_date = timezone.now()
        start_date = end_date - timezone.timedelta(days=days)
        
        # Build queryset
        queryset = self.get_queryset().filter(
            medical_record_id=medical_record_id,
            measurement_type=measurement_type,
            measured_at__range=(start_date, end_date)
        ).order_by('measured_at')
        
        # Serialize the data
        vitals_data = VitalSignSerializer(
            queryset,
            many=True,
            context=self.get_serializer_context()
        ).data
        
        # Calculate statistics
        values = []
        for vital in queryset:
            try:
                if measurement_type == 'blood_pressure':
                    # Parse systolic from blood pressure string (e.g., "120/80")
                    systolic = int(vital.blood_pressure.split('/')[0])
                    values.append(systolic)
                elif measurement_type == 'heart_rate' and vital.heart_rate:
                    values.append(vital.heart_rate)
                elif measurement_type == 'temperature' and vital.temperature:
                    values.append(float(vital.temperature))
                elif measurement_type == 'oxygen_saturation' and vital.oxygen_saturation:
                    values.append(vital.oxygen_saturation)
                elif measurement_type == 'respiratory_rate' and vital.respiratory_rate:
                    values.append(vital.respiratory_rate)
                else:
                    try:
                        # For other types, try to convert the value to float
                        values.append(float(vital.value))
                    except (ValueError, TypeError):
                        pass
            except Exception:
                continue
        
        statistics = {}
        if values:
            statistics = {
                'average': sum(values) / len(values),
                'minimum': min(values),
                'maximum': max(values),
                'count': len(values),
                'first': values[0] if values else None,
                'last': values[-1] if values else None,
            }
            if len(values) > 1:
                statistics['change'] = values[-1] - values[0]
                statistics['percent_change'] = (values[-1] - values[0]) / values[0] * 100 if values[0] else 0
        
        # Log access
        try:
            medical_record = MedicalRecord.objects.get(id=medical_record_id)
            self.log_access(medical_record, 'view', f"Vital sign trends for {measurement_type}")
        except MedicalRecord.DoesNotExist:
            pass
        
        return Response({
            'measurement_type': measurement_type,
            'time_range': {
                'start_date': start_date,
                'end_date': end_date,
                'days': days
            },
            'vitals': vitals_data,
            'statistics': statistics,
        })


class TreatmentViewSet(BaseHealthcareViewSet):
    """ViewSet for treatments."""
    queryset = Treatment.objects.all()
    serializer_class = TreatmentSerializer
    permission_classes = [permissions.IsAuthenticated, IsApprovedUser, HasHealthDataConsent]
    filterset_fields = ['medical_record', 'status', 'treatment_type', 'for_rare_condition', 
                      'related_condition', 'is_experimental', 'part_of_clinical_trial']
    search_fields = ['name', 'location', 'notes', 'reason']
    ordering_fields = ['start_date', 'end_date', 'created_at']
    
    def get_queryset(self):
        """Filter treatments based on user role and permissions."""
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        queryset = super().get_queryset()
        
        # Filter queryset based on role
        if user.role == 'patient':
            return queryset.filter(medical_record__patient=user)
        elif user.role == 'provider':
            return queryset.filter(
                Q(provider=user) |
                Q(medical_record__primary_physician=user) |
                Q(medical_record__patient__in=user.primary_patients.all())
            )
        elif user.role == 'caregiver' and hasattr(user, 'caregiver_profile'):
            # Get patients this caregiver is authorized for
            authorized_patients = user.caregiver_patients.all()
            return queryset.filter(medical_record__patient__in=authorized_patients)
        elif user.role == 'researcher' and hasattr(user, 'researcher_profile'):
            if user.researcher_profile.is_verified:
                # Researchers can only see treatments with research consent
                return queryset.filter(medical_record__research_participation_consent=True)
            return Treatment.objects.none()
        
        # Admin or staff can see all
        if user.is_staff or user.role == 'admin':
            return queryset
            
        return Treatment.objects.none()
    
    @action(detail=True, methods=['post'])
    def update_status(self, request, pk=None):
        """Update the status of a treatment."""
        treatment = self.get_object()
        new_status = request.data.get('status')
        
        # Validate status
        if new_status not in dict(Treatment.Status.choices).keys():
            return Response(
                {"error": f"Invalid status. Must be one of: {', '.join(dict(Treatment.Status.choices).keys())}"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Update status and end date if applicable
        treatment.status = new_status
        if new_status == 'completed' and not treatment.end_date:
            treatment.end_date = timezone.now().date()
        
        # Update additional fields if provided
        if 'outcome' in request.data:
            treatment.outcome = request.data['outcome']
        if 'complications' in request.data:
            treatment.complications = request.data['complications']
        if 'follow_up_required' in request.data:
            treatment.follow_up_required = request.data['follow_up_required']
        if 'follow_up_notes' in request.data:
            treatment.follow_up_notes = request.data['follow_up_notes']
        
        treatment.save()
        
        # Log the update
        self.log_access(treatment, 'update', f"Status updated to {new_status}")
        
        return Response(TreatmentSerializer(treatment, context=self.get_serializer_context()).data)


class FamilyHistoryViewSet(BaseHealthcareViewSet):
    """ViewSet for family history."""
    queryset = FamilyHistory.objects.all()
    serializer_class = FamilyHistorySerializer
    permission_classes = [permissions.IsAuthenticated, IsApprovedUser, HasHealthDataConsent]
    filterset_fields = ['medical_record', 'relationship', 'is_deceased', 'is_rare_condition']
    search_fields = ['condition', 'notes']
    ordering_fields = ['relationship', 'created_at']
    
    def get_queryset(self):
        """Filter family history based on user role and permissions."""
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        queryset = super().get_queryset()
        
        # Filter queryset based on role
        if user.role == 'patient':
            return queryset.filter(medical_record__patient=user)
        elif user.role == 'provider':
            return queryset.filter(
                Q(medical_record__primary_physician=user) |
                Q(medical_record__patient__in=user.primary_patients.all())
            )
        elif user.role == 'caregiver' and hasattr(user, 'caregiver_profile'):
            # Get patients this caregiver is authorized for
            authorized_patients = user.caregiver_patients.all()
            return queryset.filter(medical_record__patient__in=authorized_patients)
        elif user.role == 'researcher' and hasattr(user, 'researcher_profile'):
            if user.researcher_profile.is_verified:
                # Researchers can only see family history with research consent
                return queryset.filter(medical_record__research_participation_consent=True)
            return FamilyHistory.objects.none()
        
        # Admin or staff can see all
        if user.is_staff or user.role == 'admin':
            return queryset
            
        return FamilyHistory.objects.none()


class HealthDataConsentViewSet(BaseHealthcareViewSet):
    """ViewSet for health data consent."""
    queryset = HealthDataConsent.objects.all()
    serializer_class = HealthDataConsentSerializer
    permission_classes = [permissions.IsAuthenticated, IsApprovedUser]
    filterset_fields = ['patient', 'consent_type', 'consented']
    ordering_fields = ['consented_at', 'updated_at']
    
    def get_queryset(self):
        """Filter consents based on user role and permissions."""
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        queryset = super().get_queryset()
        
        # Filter queryset based on role
        if user.role == 'patient':
            return queryset.filter(patient=user)
        elif user.role == 'provider':
            # Providers can see consents where they are the authorized entity
            return queryset.filter(
                Q(authorized_entity=user) |
                Q(patient__in=user.primary_patients.all())
            )
        elif user.role == 'caregiver' and hasattr(user, 'caregiver_profile'):
            # Caregivers can see consents where they are the authorized entity
            return queryset.filter(authorized_entity=user)
        elif user.role == 'compliance' and hasattr(user, 'compliance_profile'):
            if user.compliance_profile.can_view_consent_logs:
                return queryset
            return HealthDataConsent.objects.none()
        
        # Admin or staff can see all
        if user.is_staff or user.role == 'admin':
            return queryset
            
        return HealthDataConsent.objects.none()
    
    @action(detail=False, methods=['get'])
    def my_consents(self, request):
        """Get all consents for the current user."""
        if request.user.role != 'patient':
            return Response(
                {"error": "Only patients can view their own consents"},
                status=status.HTTP_403_FORBIDDEN
            )
            
        # Get consents
        consents = self.get_queryset().filter(patient=request.user)
        
        # Serialize the data
        consents_data = HealthDataConsentSerializer(
            consents,
            many=True,
            context=self.get_serializer_context()
        ).data
        
        return Response({
            'consents': consents_data,
            'count': consents.count(),
        })
    
    @action(detail=False, methods=['post'])
    def update_consent(self, request):
        """Update or create a consent record."""
        consent_type = request.data.get('consent_type')
        consented = request.data.get('consented', False)
        authorized_entity_id = request.data.get('authorized_entity_id')
        
        if not consent_type:
            return Response(
                {"error": "consent_type parameter is required"},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        # Validate consent type
        valid_types = dict(HealthDataConsent.CONSENT_TYPES).keys()
        if consent_type not in valid_types:
            return Response(
                {"error": f"Invalid consent_type. Must be one of: {', '.join(valid_types)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get or create consent
        data = {
            'patient': request.user.id,
            'consent_type': consent_type,
            'consented': consented
        }
        
        if authorized_entity_id:
            try:
                authorized_entity = User.objects.get(id=authorized_entity_id)
                data['authorized_entity'] = authorized_entity.id
            except User.DoesNotExist:
                return Response(
                    {"error": "Authorized entity not found"},
                    status=status.HTTP_404_NOT_FOUND
                )
        
        # Try to find existing consent
        try:
            consent = HealthDataConsent.objects.get(
                patient=request.user,
                consent_type=consent_type,
                authorized_entity_id=authorized_entity_id
            )
            serializer = HealthDataConsentSerializer(
                consent, 
                data=data,
                context=self.get_serializer_context()
            )
        except HealthDataConsent.DoesNotExist:
            serializer = HealthDataConsentSerializer(
                data=data,
                context=self.get_serializer_context()
            )
        
        # Save the consent
        serializer.is_valid(raise_exception=True)
        consent = serializer.save()
        
        # Update user consent flags if applicable
        if consent_type == 'medication_tracking' and hasattr(request.user, 'patient_profile'):
            request.user.medication_adherence_monitoring_consent = consented
            request.user.patient_profile.medication_adherence_opt_in = consented
            request.user.patient_profile.medication_adherence_consent_date = timezone.now() if consented else None
            request.user.save(update_fields=['medication_adherence_monitoring_consent'])
            request.user.patient_profile.save(update_fields=['medication_adherence_opt_in', 'medication_adherence_consent_date'])
        
        elif consent_type == 'vitals_monitoring' and hasattr(request.user, 'patient_profile'):
            request.user.vitals_monitoring_consent = consented
            request.user.patient_profile.vitals_monitoring_opt_in = consented
            request.user.patient_profile.vitals_monitoring_consent_date = timezone.now() if consented else None
            request.user.save(update_fields=['vitals_monitoring_consent'])
            request.user.patient_profile.save(update_fields=['vitals_monitoring_opt_in', 'vitals_monitoring_consent_date'])
        
        elif consent_type == 'research' and hasattr(request.user, 'patient_profile'):
            request.user.research_consent = consented
            request.user.save(update_fields=['research_consent'])
            
            # Update medical record research consent
            try:
                medical_record = request.user.medical_records.first()
                if medical_record:
                    medical_record.research_participation_consent = consented
                    medical_record.research_consent_date = timezone.now() if consented else None
                    medical_record.save(update_fields=['research_participation_consent', 'research_consent_date'])
            except Exception:
                pass
        
        return Response(HealthDataConsentSerializer(consent, context=self.get_serializer_context()).data)


class HealthDataAuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for health data audit logs."""
    queryset = HealthDataAuditLog.objects.all()
    serializer_class = HealthDataAuditLogSerializer
    permission_classes = [permissions.IsAuthenticated, IsApprovedUser, CanViewAuditLogs]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['user', 'action', 'resource_type', 'patient_id']
    ordering_fields = ['timestamp']
    
    def get_queryset(self):
        """Filter audit logs based on user role and permissions."""
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        queryset = super().get_queryset()
        
        # Filter queryset based on role
        if user.role == 'compliance' and hasattr(user, 'compliance_profile'):
            if user.compliance_profile.can_view_audit_logs:
                return queryset
            return HealthDataAuditLog.objects.none()
        
        # Admin or staff can see all
        if user.is_staff or user.role == 'admin':
            return queryset
            
        return HealthDataAuditLog.objects.none()
    
    @action(detail=False, methods=['get'])
    def statistics(self, request):
        """Get audit log statistics."""
        if not (request.user.is_staff or request.user.role == 'admin' or 
                (request.user.role == 'compliance' and hasattr(request.user, 'compliance_profile') and 
                request.user.compliance_profile.can_view_audit_logs)):
            return Response(
                {"error": "You do not have permission to access audit statistics"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Get time range parameters
        days = int(request.query_params.get('days', 30))
        end_date = timezone.now()
        start_date = end_date - timezone.timedelta(days=days)
        
        # Get audit logs in time range
        queryset = self.get_queryset().filter(timestamp__range=(start_date, end_date))
        
        # Calculate statistics
        total_logs = queryset.count()
        
        # Logs by action type
        action_stats = queryset.values('action').annotate(
            count=Count('id')
        ).order_by('-count')
        
        # Logs by resource type
        resource_stats = queryset.values('resource_type').annotate(
            count=Count('id')
        ).order_by('-count')
        
        # Logs by user role
        role_stats = queryset.values('user__role').annotate(
            count=Count('id')
        ).order_by('-count')
        
        # Top users
        user_stats = queryset.values('user__username', 'user__role').annotate(
            count=Count('id')
        ).order_by('-count')[:10]
        
        return Response({
            'time_range': {
                'start_date': start_date,
                'end_date': end_date,
                'days': days
            },
            'total_logs': total_logs,
            'by_action': action_stats,
            'by_resource': resource_stats,
            'by_role': role_stats,
            'top_users': user_stats,
        })


class EHRIntegrationViewSet(BaseHealthcareViewSet):
    """ViewSet for EHR integrations."""
    queryset = EHRIntegration.objects.all()
    serializer_class = EHRIntegrationSerializer
    permission_classes = [permissions.IsAuthenticated, IsApprovedUser]
    filterset_fields = ['patient', 'integration_type', 'status']
    ordering_fields = ['created_at', 'updated_at', 'last_sync']
    
    def get_queryset(self):
        """Filter EHR integrations based on user role and permissions."""
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        queryset = super().get_queryset()
        
        # Filter queryset based on role
        if user.role == 'patient':
            return queryset.filter(patient=user)
        elif user.role == 'provider':
            return queryset.filter(
                Q(patient__in=user.primary_patients.all())
            )
        
        # Admin or staff can see all
        if user.is_staff or user.role == 'admin':
            return queryset
            
        return EHRIntegration.objects.none()
    
    @action(detail=True, methods=['post'])
    def sync(self, request, pk=None):
        """Trigger synchronization with EHR system."""
        integration = self.get_object()
        
        # Check if integration is active
        if integration.status != 'active':
            return Response(
                {"error": "Cannot sync inactive integration"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if tokens are valid
        if not integration.access_token or not integration.token_expiry or integration.token_expiry < timezone.now():
            return Response(
                {"error": "Integration tokens are expired or missing"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Log the sync attempt
        self.log_access(integration, 'view', "EHR sync triggered")
        
        # In a real implementation, this would call an async task to sync with the EHR
        # For now, just update the last_sync timestamp
        integration.last_sync = timezone.now()
        integration.save(update_fields=['last_sync'])
        
        return Response({
            "success": True,
            "message": "Synchronization started",
            "last_sync": integration.last_sync
        })


class WearableIntegrationViewSet(BaseHealthcareViewSet):
    """ViewSet for wearable device integrations."""
    queryset = WearableIntegration.objects.all()
    serializer_class = WearableIntegrationSerializer
    permission_classes = [permissions.IsAuthenticated, IsApprovedUser]
    filterset_fields = ['patient', 'device_type', 'status']
    ordering_fields = ['created_at', 'updated_at', 'last_sync']
    
    def get_queryset(self):
        """Filter wearable integrations based on user role and permissions."""
        if getattr(self, 'swagger_fake_view', False):
            # Return an empty queryset for swagger schema generation
            return self.queryset.model.objects.none()
        
        user = self.request.user
        queryset = super().get_queryset()
        
        # Filter queryset based on role
        if user.role == 'patient':
            return queryset.filter(patient=user)
        elif user.role == 'provider':
            return queryset.filter(
                Q(patient__in=user.primary_patients.all())
            )
        elif user.role == 'caregiver' and hasattr(user, 'caregiver_profile'):
            # Get patients this caregiver is authorized for
            authorized_patients = user.caregiver_patients.all()
            return queryset.filter(patient__in=authorized_patients)
        
        # Admin or staff can see all
        if user.is_staff or user.role == 'admin':
            return queryset
            
        return WearableIntegration.objects.none()
    
    @action(detail=True, methods=['post'])
    def sync(self, request, pk=None):
        """Trigger synchronization with wearable device."""
        integration = self.get_object()
        
        # Check if integration is active
        if integration.status != 'active':
            return Response(
                {"error": "Cannot sync inactive integration"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if tokens are valid
        if not integration.access_token or not integration.token_expiry or integration.token_expiry < timezone.now():
            return Response(
                {"error": "Integration tokens are expired or missing"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if consent is granted
        if not integration.consent_granted:
            return Response(
                {"error": "Missing consent for wearable data integration"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Log the sync attempt
        self.log_access(integration, 'view', "Wearable sync triggered")
        
        # In a real implementation, this would call an async task to sync with the wearable API
        # For now, just update the last_sync timestamp
        integration.last_sync = timezone.now()
        integration.save(update_fields=['last_sync'])
        
        return Response({
            "success": True,
            "message": "Synchronization started",
            "last_sync": integration.last_sync
        })


class RareConditionRegistryViewSet(BaseHealthcareViewSet):
    """ViewSet for rare condition registry."""
    queryset = RareConditionRegistry.objects.all()
    serializer_class = RareConditionRegistrySerializer
    permission_classes = [permissions.IsAuthenticated, IsApprovedUser]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter, filters.SearchFilter]
    search_fields = ['name', 'identifier', 'description', 'specialty_category']
    ordering_fields = ['name', 'created_at']
    
    def get_permissions(self):
        """Allow read access to all, but only admins and providers can add/edit."""
        if self.action in ['list', 'retrieve']:
            return [permissions.IsAuthenticated(), IsApprovedUser()]
        return [permissions.IsAuthenticated(), IsApprovedUser(), IsProviderOnly()]
    
    @action(detail=True, methods=['get'])
    def patients(self, request, pk=None):
        """Get patients with this rare condition."""
        condition = self.get_object()
        
        # Check if user is authorized to view patient data
        if not (request.user.is_staff or request.user.role in ['admin', 'provider']):
            return Response(
                {"error": "You do not have permission to view patient data"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Get patients with this condition
        from users.models import User
        from users.serializers import UserSerializer
        
        patients = User.objects.filter(
            role='patient',
            medical_records__conditions__rare_condition=condition,
            medical_records__conditions__is_rare_condition=True
        ).distinct()
        
        # Filter to only provider's patients if not admin
        if not (request.user.is_staff or request.user.role == 'admin'):
            patients = patients.filter(
                Q(medical_records__primary_physician=request.user) |
                Q(id__in=request.user.primary_patients.values_list('id', flat=True))
            )
        
        # Log the access
        self.log_access(condition, 'view', "Patient list by rare condition")
        
        # Serialize the data
        patients_data = UserSerializer(
            patients,
            many=True,
            context=self.get_serializer_context()
        ).data
        
        return Response({
            'condition': RareConditionRegistrySerializer(condition, context=self.get_serializer_context()).data,
            'patients': patients_data,
            'count': patients.count(),
        })


class ReferralNetworkViewSet(BaseHealthcareViewSet):
    """ViewSet for rare condition specialist referral network."""
    queryset = ReferralNetwork.objects.all()
    serializer_class = ReferralNetworkSerializer
    permission_classes = [permissions.IsAuthenticated, IsApprovedUser, IsProviderForReferral]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter, filters.SearchFilter]
    filterset_fields = ['specialty', 'rare_conditions_specialty', 'accepting_patients', 'telemedicine_available']
    search_fields = ['provider__first_name', 'provider__last_name', 'specialty', 'location']
    ordering_fields = ['specialty', 'years_experience', 'location']
    
    @action(detail=False, methods=['get'])
    def by_condition(self, request):
        """Find specialists for a specific rare condition."""
        condition_id = request.query_params.get('condition_id')
        
        if not condition_id:
            return Response(
                {"error": "condition_id parameter is required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            rare_condition = RareConditionRegistry.objects.get(id=condition_id)
        except RareConditionRegistry.DoesNotExist:
            return Response(
                {"error": "Rare condition not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Get specialists for this condition
        specialists = self.get_queryset().filter(
            Q(specific_conditions=rare_condition) |
            Q(rare_conditions_specialty=True)
        ).distinct()
        
        # Additional filters
        accepting_patients = request.query_params.get('accepting_patients')
        if accepting_patients is not None:
            specialists = specialists.filter(accepting_patients=(accepting_patients.lower() == 'true'))
        
        telemedicine = request.query_params.get('telemedicine')
        if telemedicine is not None:
            specialists = specialists.filter(telemedicine_available=(telemedicine.lower() == 'true'))
        
        # Serialize the data
        specialists_data = ReferralNetworkSerializer(
            specialists,
            many=True,
            context=self.get_serializer_context()
        ).data
        
        return Response({
            'condition': RareConditionRegistrySerializer(rare_condition, context=self.get_serializer_context()).data,
            'specialists': specialists_data,
            'count': specialists.count(),
        })
