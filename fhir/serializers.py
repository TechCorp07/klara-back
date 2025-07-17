"""
Serializers for FHIR resources.
Provides serialization and deserialization functionality for all FHIR resource types.
"""
from rest_framework import serializers
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


class FHIRBaseSerializer(serializers.Serializer):
    """
    Base serializer for all FHIR resources.
    Handles common fields and functionality.
    """
    id = serializers.UUIDField(read_only=True)
    resourceType = serializers.CharField(read_only=True)
    identifier = serializers.ListField(child=serializers.DictField(), required=False)
    meta = serializers.DictField(required=False)
    text = serializers.DictField(required=False)
    extension = serializers.ListField(child=serializers.DictField(), required=False)
    
    def to_representation(self, instance):
        return instance.to_fhir()
    
    def to_internal_value(self, data):
        resource_type = data.get('resourceType')
        if not resource_type:
            raise serializers.ValidationError({"resourceType": "This field is required."})
        if resource_type != self.Meta.resource_type:
            raise serializers.ValidationError({"resourceType": f"Expected {self.Meta.resource_type}, got {resource_type}."})
        return data
    
    def create(self, validated_data):
        model_class = self.Meta.model
        return model_class.from_fhir(validated_data)
    
    def update(self, instance, validated_data):
        model_class = self.Meta.model
        if 'id' not in validated_data and instance.id:
            validated_data['id'] = str(instance.id)
        return model_class.from_fhir(validated_data)


class FHIRPatientSerializer(FHIRBaseSerializer):
    class Meta:
        model = FHIRPatient
        resource_type = "Patient"
        fields = '__all__'


class FHIRPractitionerSerializer(FHIRBaseSerializer):
    class Meta:
        model = FHIRPractitioner
        resource_type = "Practitioner"
        fields = '__all__'


class FHIROrganizationSerializer(FHIRBaseSerializer):
    class Meta:
        model = FHIROrganization
        resource_type = "Organization"
        fields = '__all__'


class FHIRObservationSerializer(FHIRBaseSerializer):
    class Meta:
        model = FHIRObservation
        resource_type = "Observation"
        fields = '__all__'


class FHIRConditionSerializer(FHIRBaseSerializer):
    class Meta:
        model = FHIRCondition
        resource_type = "Condition"
        fields = '__all__'


class FHIRMedicationStatementSerializer(FHIRBaseSerializer):
    class Meta:
        model = FHIRMedicationStatement
        resource_type = "MedicationStatement"
        fields = '__all__'


class FHIRCommunicationSerializer(FHIRBaseSerializer):
    class Meta:
        model = FHIRCommunication
        resource_type = "Communication"
        fields = '__all__'


class FHIREncounterSerializer(FHIRBaseSerializer):
    class Meta:
        model = FHIREncounter
        resource_type = "Encounter"
        fields = '__all__'


__all__ = [
    'FHIRBaseSerializer',
    'FHIRPatientSerializer',
    'FHIRPractitionerSerializer',
    'FHIROrganizationSerializer',
    'FHIRObservationSerializer',
    'FHIRConditionSerializer',
    'FHIRMedicationStatementSerializer',
    'FHIRCommunicationSerializer',
    'FHIREncounterSerializer',
]
