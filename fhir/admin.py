from django.contrib import admin
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


@admin.register(FHIRPatient)
class FHIRPatientAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'identifier', 'name', 'birth_date', 'gender', 'created_at', 'updated_at')
    search_fields = ('identifier', 'name')
    list_filter = ('gender', 'created_at', 'updated_at')


@admin.register(FHIRPractitioner)
class FHIRPractitionerAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'identifier', 'name', 'qualification', 'created_at', 'updated_at')
    search_fields = ('identifier', 'name', 'qualification')
    list_filter = ('created_at', 'updated_at')


@admin.register(FHIROrganization)
class FHIROrganizationAdmin(admin.ModelAdmin):
    list_display = ('id', 'identifier', 'name', 'type', 'created_at', 'updated_at')
    search_fields = ('identifier', 'name')
    list_filter = ('type', 'created_at', 'updated_at')


@admin.register(FHIRObservation)
class FHIRObservationAdmin(admin.ModelAdmin):
    list_display = ('id', 'patient', 'code', 'value', 'unit', 'effective_date', 'created_at', 'updated_at')
    search_fields = ('patient__name', 'code')
    list_filter = ('code', 'effective_date', 'created_at')


@admin.register(FHIRCondition)
class FHIRConditionAdmin(admin.ModelAdmin):
    list_display = ('id', 'patient', 'code', 'clinical_status', 'severity', 'onset_date', 'created_at', 'updated_at')
    search_fields = ('patient__name', 'code')
    list_filter = ('clinical_status', 'severity', 'created_at')


@admin.register(FHIRMedicationStatement)
class FHIRMedicationStatementAdmin(admin.ModelAdmin):
    list_display = ('id', 'patient', 'medication', 'status', 'effective_date', 'created_at', 'updated_at')
    search_fields = ('patient__name', 'medication')
    list_filter = ('status', 'effective_date', 'created_at')


@admin.register(FHIRCommunication)
class FHIRCommunicationAdmin(admin.ModelAdmin):
    list_display = ('id', 'sender', 'recipient', 'status', 'sent', 'created_at', 'updated_at')
    search_fields = ('sender__name', 'recipient__name')
    list_filter = ('status', 'sent', 'created_at')


@admin.register(FHIREncounter)
class FHIREncounterAdmin(admin.ModelAdmin):
    list_display = ('id', 'patient', 'status', 'class_code', 'start', 'end', 'created_at', 'updated_at')
    search_fields = ('patient__name',)
    list_filter = ('status', 'class_code', 'start', 'created_at')
