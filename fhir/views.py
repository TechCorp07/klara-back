"""
Views for FHIR resources.
Provides API endpoints for all FHIR resource types.
"""
from rest_framework import viewsets, status, permissions
from rest_framework.response import Response
from rest_framework.decorators import action
from django.http import Http404
import json
import logging

from fhir.models import (
    FHIRPatient,
    FHIRPractitioner,
    FHIROrganization,
    FHIRObservation,
    FHIRCondition,
    FHIRMedicationStatement,
    FHIRCommunication,
    FHIREncounter
)
from fhir.serializers import (
    FHIRPatientSerializer,
    FHIRPractitionerSerializer,
    FHIROrganizationSerializer,
    FHIRObservationSerializer,
    FHIRConditionSerializer,
    FHIRMedicationStatementSerializer,
    FHIRCommunicationSerializer,
    FHIREncounterSerializer
)

logger = logging.getLogger('fhir')


class FHIRBaseViewSet(viewsets.ModelViewSet):
    resource_type = None
    
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
    
    def create(self, request, *args, **kwargs):
        data = request.data.copy()
        if 'resourceType' not in data:
            data['resourceType'] = self.resource_type
        elif data['resourceType'] != self.resource_type:
            return Response(
                {"error": f"Resource type mismatch. Expected {self.resource_type}, got {data['resourceType']}."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)
    
    def update(self, request, *args, **kwargs):
        data = request.data.copy()
        if 'resourceType' not in data:
            data['resourceType'] = self.resource_type
        elif data['resourceType'] != self.resource_type:
            return Response(
                {"error": f"Resource type mismatch. Expected {self.resource_type}, got {data['resourceType']}."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        
        if 'id' not in data:
            data['id'] = str(instance.id)
        
        serializer = self.get_serializer(instance, data=data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        
        if getattr(instance, '_prefetched_objects_cache', None):
            instance._prefetched_objects_cache = {}
        return Response(serializer.data)
    
    @action(detail=False, methods=['post'])
    def search(self, request):
        queryset = self.filter_queryset(self.get_queryset())
        search_params = request.data.get('parameters', {})
        for param, value in search_params.items():
            filter_kwargs = self._parse_search_param(param, value)
            if filter_kwargs:
                queryset = queryset.filter(**filter_kwargs)
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)
    
    def _parse_search_param(self, param, value):
        return {}
    
    @action(detail=False, methods=['post'])
    def batch(self, request):
        if 'resourceType' not in request.data or request.data['resourceType'] != 'Bundle':
            return Response({"error": "Expected a Bundle resource."}, status=status.HTTP_400_BAD_REQUEST)
        if 'type' not in request.data or request.data['type'] != 'batch':
            return Response({"error": "Only batch bundles are supported."}, status=status.HTTP_400_BAD_REQUEST)
        if 'entry' not in request.data:
            return Response({"error": "Bundle must contain entries."}, status=status.HTTP_400_BAD_REQUEST)
        
        results = []
        for entry in request.data['entry']:
            if 'request' not in entry or 'resource' not in entry:
                results.append({
                    "status": "400",
                    "outcome": {"issue": [
                        {"severity": "error", "code": "invalid", "diagnostics": "Entry must contain request and resource."}
                    ]}
                })
                continue
            request_details = entry['request']
            resource = entry['resource']
            
            if resource.get('resourceType') != self.resource_type:
                results.append({
                    "status": "400",
                    "outcome": {"issue": [
                        {"severity": "error", "code": "invalid", "diagnostics": f"Resource type mismatch. Expected {self.resource_type}, got {resource.get('resourceType')}."}
                    ]}
                })
                continue
            
            method = request_details.get('method', 'POST').upper()
            
            try:
                if method == 'POST':
                    serializer = self.get_serializer(data=resource)
                    serializer.is_valid(raise_exception=True)
                    self.perform_create(serializer)
                    results.append({
                        "status": "201",
                        "location": f"{self.resource_type}/{serializer.data['id']}",
                        "resource": serializer.data
                    })
                elif method == 'PUT':
                    url_parts = request_details.get('url', '').split('/')
                    if len(url_parts) < 2:
                        results.append({
                            "status": "400",
                            "outcome": {"issue": [
                                {"severity": "error", "code": "invalid", "diagnostics": "Invalid URL format for PUT request."}
                            ]}
                        })
                        continue
                    resource_id = url_parts[-1]
                    try:
                        instance = self.queryset.get(id=resource_id)
                    except self.queryset.model.DoesNotExist:
                        results.append({
                            "status": "404",
                            "outcome": {"issue": [
                                {"severity": "error", "code": "not-found", "diagnostics": f"Resource {self.resource_type}/{resource_id} not found."}
                            ]}
                        })
                        continue
                    resource['id'] = resource_id
                    serializer = self.get_serializer(instance, data=resource)
                    serializer.is_valid(raise_exception=True)
                    self.perform_update(serializer)
                    results.append({
                        "status": "200",
                        "location": f"{self.resource_type}/{resource_id}",
                        "resource": serializer.data
                    })
                elif method == 'DELETE':
                    url_parts = request_details.get('url', '').split('/')
                    if len(url_parts) < 2:
                        results.append({
                            "status": "400",
                            "outcome": {"issue": [
                                {"severity": "error", "code": "invalid", "diagnostics": "Invalid URL format for DELETE request."}
                            ]}
                        })
                        continue
                    resource_id = url_parts[-1]
                    try:
                        instance = self.queryset.get(id=resource_id)
                    except self.queryset.model.DoesNotExist:
                        results.append({
                            "status": "404",
                            "outcome": {"issue": [
                                {"severity": "error", "code": "not-found", "diagnostics": f"Resource {self.resource_type}/{resource_id} not found."}
                            ]}
                        })
                        continue
                    self.perform_destroy(instance)
                    results.append({"status": "204"})
                else:
                    results.append({
                        "status": "405",
                        "outcome": {"issue": [
                            {"severity": "error", "code": "not-supported", "diagnostics": f"Method {method} not supported."}
                        ]}
                    })
            except Exception as e:
                logger.exception(f"Error processing batch entry: {e}")
                results.append({
                    "status": "500",
                    "outcome": {"issue": [
                        {"severity": "error", "code": "exception", "diagnostics": str(e)}
                    ]}
                })
        
        return Response({
            "resourceType": "Bundle",
            "type": "batch-response",
            "entry": results
        })


class FHIRPatientViewSet(FHIRBaseViewSet):
    queryset = FHIRPatient.objects.all()
    serializer_class = FHIRPatientSerializer
    permission_classes = [permissions.IsAuthenticated]
    resource_type = "Patient"
    
    def _parse_search_param(self, param, value):
        filter_kwargs = {}
        if param == 'name':
            filter_kwargs['name__icontains'] = value
        elif param == 'identifier':
            filter_kwargs['identifier'] = value
        elif param == 'gender':
            filter_kwargs['gender'] = value
        elif param == 'birthdate':
            filter_kwargs['birth_date'] = value
        elif param == 'active':
            filter_kwargs['active'] = value.lower() == 'true'
        return filter_kwargs


class FHIRPractitionerViewSet(FHIRBaseViewSet):
    queryset = FHIRPractitioner.objects.all()
    serializer_class = FHIRPractitionerSerializer
    permission_classes = [permissions.IsAuthenticated]
    resource_type = "Practitioner"
    
    def _parse_search_param(self, param, value):
        filter_kwargs = {}
        if param == 'name':
            filter_kwargs['name__icontains'] = value
        elif param == 'identifier':
            filter_kwargs['identifier'] = value
        elif param == 'active':
            filter_kwargs['active'] = value.lower() == 'true'
        elif param == 'qualification':
            filter_kwargs['qualification__icontains'] = value
        return filter_kwargs


class FHIROrganizationViewSet(FHIRBaseViewSet):
    queryset = FHIROrganization.objects.all()
    serializer_class = FHIROrganizationSerializer
    permission_classes = [permissions.IsAuthenticated]
    resource_type = "Organization"
    
    def _parse_search_param(self, param, value):
        filter_kwargs = {}
        if param == 'name':
            filter_kwargs['name__icontains'] = value
        elif param == 'identifier':
            filter_kwargs['identifier'] = value
        elif param == 'active':
            filter_kwargs['active'] = value.lower() == 'true'
        elif param == 'type':
            filter_kwargs['type'] = value
        return filter_kwargs


class FHIRObservationViewSet(FHIRBaseViewSet):
    queryset = FHIRObservation.objects.all()
    serializer_class = FHIRObservationSerializer
    permission_classes = [permissions.IsAuthenticated]
    resource_type = "Observation"
    
    def _parse_search_param(self, param, value):
        filter_kwargs = {}
        if param == 'patient':
            if value.startswith('Patient/'):
                patient_id = value.split('/')[-1]
                filter_kwargs['patient__id'] = patient_id
            else:
                filter_kwargs['patient__id'] = value
        elif param == 'code':
            filter_kwargs['code'] = value
        elif param == 'category':
            filter_kwargs['category'] = value
        elif param == 'date':
            if value.startswith('gt'):
                filter_kwargs['effective_date__gt'] = value[2:]
            elif value.startswith('lt'):
                filter_kwargs['effective_date__lt'] = value[2:]
            elif value.startswith('ge'):
                filter_kwargs['effective_date__gte'] = value[2:]
            elif value.startswith('le'):
                filter_kwargs['effective_date__lte'] = value[2:]
            else:
                filter_kwargs['effective_date'] = value
        elif param == 'status':
            filter_kwargs['status'] = value
        elif param == 'is_nmosd_indicator':
            filter_kwargs['is_nmosd_indicator'] = value.lower() == 'true'
        elif param == 'nmosd_indicator_type':
            filter_kwargs['nmosd_indicator_type'] = value
        elif param == 'wearable_source':
            filter_kwargs['wearable_source'] = value
        return filter_kwargs


class FHIRConditionViewSet(FHIRBaseViewSet):
    queryset = FHIRCondition.objects.all()
    serializer_class = FHIRConditionSerializer
    permission_classes = [permissions.IsAuthenticated]
    resource_type = "Condition"
    
    def _parse_search_param(self, param, value):
        filter_kwargs = {}
        if param == 'patient':
            if value.startswith('Patient/'):
                patient_id = value.split('/')[-1]
                filter_kwargs['patient__id'] = patient_id
            else:
                filter_kwargs['patient__id'] = value
        elif param == 'code':
            filter_kwargs['code'] = value
        elif param == 'clinical-status':
            filter_kwargs['clinical_status'] = value
        elif param == 'verification-status':
            filter_kwargs['verification_status'] = value
        elif param == 'category':
            filter_kwargs['category'] = value
        elif param == 'severity':
            filter_kwargs['severity'] = value
        elif param == 'onset-date':
            if value.startswith('gt'):
                filter_kwargs['onset_date__gt'] = value[2:]
            elif value.startswith('lt'):
                filter_kwargs['onset_date__lt'] = value[2:]
            elif value.startswith('ge'):
                filter_kwargs['onset_date__gte'] = value[2:]
            elif value.startswith('le'):
                filter_kwargs['onset_date__lte'] = value[2:]
            else:
                filter_kwargs['onset_date'] = value
        elif param == 'is-nmosd':
            filter_kwargs['is_nmosd'] = value.lower() == 'true'
        elif param == 'nmosd-subtype':
            filter_kwargs['nmosd_subtype'] = value
        return filter_kwargs


class FHIRMedicationStatementViewSet(FHIRBaseViewSet):
    queryset = FHIRMedicationStatement.objects.all()
    serializer_class = FHIRMedicationStatementSerializer
    permission_classes = [permissions.IsAuthenticated]
    resource_type = "MedicationStatement"
    
    def _parse_search_param(self, param, value):
        filter_kwargs = {}
        if param == 'patient':
            if value.startswith('Patient/'):
                patient_id = value.split('/')[-1]
                filter_kwargs['patient__id'] = patient_id
            else:
                filter_kwargs['patient__id'] = value
        elif param == 'medication':
            filter_kwargs['medication__icontains'] = value
        elif param == 'medication-code':
            filter_kwargs['medication_code'] = value
        elif param == 'status':
            filter_kwargs['status'] = value
        elif param == 'effective-date':
            if value.startswith('gt'):
                filter_kwargs['effective_date__gt'] = value[2:]
            elif value.startswith('lt'):
                filter_kwargs['effective_date__lt'] = value[2:]
            elif value.startswith('ge'):
                filter_kwargs['effective_date__gte'] = value[2:]
            elif value.startswith('le'):
                filter_kwargs['effective_date__lte'] = value[2:]
            else:
                filter_kwargs['effective_date'] = value
        elif param == 'adherence-status':
            filter_kwargs['adherence_status'] = value
        elif param == 'adherence-score':
            if value.startswith('gt'):
                filter_kwargs['adherence_score__gt'] = int(value[2:])
            elif value.startswith('lt'):
                filter_kwargs['adherence_score__lt'] = int(value[2:])
            elif value.startswith('ge'):
                filter_kwargs['adherence_score__gte'] = int(value[2:])
            elif value.startswith('le'):
                filter_kwargs['adherence_score__lte'] = int(value[2:])
            else:
                filter_kwargs['adherence_score'] = int(value)
        return filter_kwargs


class FHIRCommunicationViewSet(FHIRBaseViewSet):
    queryset = FHIRCommunication.objects.all()
    serializer_class = FHIRCommunicationSerializer
    permission_classes = [permissions.IsAuthenticated]
    resource_type = "Communication"
    
    def _parse_search_param(self, param, value):
        filter_kwargs = {}
        if param == 'patient':
            if value.startswith('Patient/'):
                patient_id = value.split('/')[-1]
                filter_kwargs['patient__id'] = patient_id
            else:
                filter_kwargs['patient__id'] = value
        elif param == 'sender':
            filter_kwargs['sender'] = value
        elif param == 'sender-type':
            filter_kwargs['sender_type'] = value
        elif param == 'recipient':
            filter_kwargs['recipient'] = value
        elif param == 'recipient-type':
            filter_kwargs['recipient_type'] = value
        elif param == 'status':
            filter_kwargs['status'] = value
        elif param == 'category':
            filter_kwargs['category'] = value
        elif param == 'sent':
            if value.startswith('gt'):
                filter_kwargs['sent__gt'] = value[2:]
            elif value.startswith('lt'):
                filter_kwargs['sent__lt'] = value[2:]
            elif value.startswith('ge'):
                filter_kwargs['sent__gte'] = value[2:]
            elif value.startswith('le'):
                filter_kwargs['sent__lte'] = value[2:]
            else:
                filter_kwargs['sent'] = value
        elif param == 'received':
            if value.startswith('gt'):
                filter_kwargs['received__gt'] = value[2:]
            elif value.startswith('lt'):
                filter_kwargs['received__lt'] = value[2:]
            elif value.startswith('ge'):
                filter_kwargs['received__gte'] = value[2:]
            elif value.startswith('le'):
                filter_kwargs['received__lte'] = value[2:]
            else:
                filter_kwargs['received'] = value
        elif param == 'medium':
            filter_kwargs['medium'] = value
        elif param == 'priority':
            filter_kwargs['priority'] = value
        elif param == 'content-type':
            filter_kwargs['content_type'] = value
        elif param == 'subject':
            filter_kwargs['subject__icontains'] = value
        elif param == 'content':
            filter_kwargs['content__icontains'] = value
        elif param == 'has-attachments':
            filter_kwargs['has_attachments'] = value.lower() == 'true'
        return filter_kwargs


class FHIREncounterViewSet(FHIRBaseViewSet):
    queryset = FHIREncounter.objects.all()
    serializer_class = FHIREncounterSerializer
    permission_classes = [permissions.IsAuthenticated]
    resource_type = "Encounter"
    
    def _parse_search_param(self, param, value):
        filter_kwargs = {}
        if param == 'patient':
            if value.startswith('Patient/'):
                patient_id = value.split('/')[-1]
                filter_kwargs['patient__id'] = patient_id
            else:
                filter_kwargs['patient__id'] = value
        elif param == 'status':
            filter_kwargs['status'] = value
        elif param == 'class':
            filter_kwargs['class_code'] = value
        elif param == 'type':
            filter_kwargs['type_code'] = value
        elif param == 'date':
            if value.startswith('gt'):
                filter_kwargs['start__gt'] = value[2:]
            elif value.startswith('lt'):
                filter_kwargs['start__lt'] = value[2:]
            elif value.startswith('ge'):
                filter_kwargs['start__gte'] = value[2:]
            elif value.startswith('le'):
                filter_kwargs['start__lte'] = value[2:]
            else:
                filter_kwargs['start'] = value
        elif param == 'service-type':
            filter_kwargs['service_type'] = value
        elif param == 'priority':
            filter_kwargs['priority'] = value
        elif param == 'location':
            filter_kwargs['location__icontains'] = value
        elif param == 'is-telemedicine':
            filter_kwargs['is_telemedicine'] = value.lower() == 'true'
        elif param == 'telemedicine-platform':
            filter_kwargs['telemedicine_platform'] = value
        return filter_kwargs


__all__ = [
    'FHIRBaseViewSet',
    'FHIRPatientViewSet',
    'FHIRPractitionerViewSet',
    'FHIROrganizationViewSet',
    'FHIRObservationViewSet',
    'FHIRConditionViewSet',
    'FHIRMedicationStatementViewSet',
    'FHIRCommunicationViewSet',
    'FHIREncounterViewSet',
]
