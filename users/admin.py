# admin.py
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils import timezone
from django.utils.html import format_html

from .models import (
    TemporaryRegistrationData, User, TwoFactorDevice, PatientProfile, ProviderProfile, 
    PharmcoProfile, CaregiverProfile, ResearcherProfile,
    ComplianceProfile, CaregiverRequest, EmergencyAccess,
    ConsentRecord, HIPAADocument, PatientAuthorizedCaregiver
)
from .utils import EmailService


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Enhanced admin configuration for User model."""
    model = User
    list_display = (
        'username', 'email', 'role', 'is_active', 'is_approved', 
        'email_verified', 'two_factor_enabled', 'date_joined'
    )
    list_filter = (
        'role', 'is_staff', 'is_superuser', 'is_active', 
        'is_approved', 'email_verified', 'two_factor_enabled'
    )
    search_fields = ('username', 'email', 'first_name', 'last_name')
    ordering = ('-date_joined',)
    
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal Info', {
            'fields': ('first_name', 'last_name', 'email', 'phone_number', 'date_of_birth')
        }),
        ('Permissions', {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')
        }),
        ('Role & Approval', {
            'fields': ('role', 'is_approved', 'approved_at', 'approved_by')
        }),
        ('Security', {
            'fields': (
                'two_factor_enabled', 'email_verified', 'login_attempts',
                'account_locked', 'account_locked_time', 'password_last_changed',
                'last_login_ip'
            )
        }),
        ('Consent Tracking', {
            'fields': (
                'terms_accepted', 'hipaa_privacy_acknowledged',
                'data_sharing_consent', 'caregiver_authorization_acknowledged',
                'phi_handling_acknowledged'
            )
        }),
        ('Important Dates', {
            'fields': ('last_login', 'date_joined')
        }),
    )
    
    readonly_fields = (
        'date_joined', 'last_login', 'approved_at', 'approved_by',
        'password_last_changed', 'last_login_ip'
    )
    
    add_fieldsets = BaseUserAdmin.add_fieldsets + (
        ('Role & Contact', {
            'fields': ('role', 'email', 'phone_number')
        }),
    )
    
    actions = [
        'approve_users', 'unlock_accounts', 'verify_emails',
        'resend_verification_emails', 'reset_login_attempts',
        'bulk_approve_users', 'export_user_data'
    ]
    
    def approve_users(self, request, queryset):
        """Bulk approve users."""
        count = 0
        for user in queryset.filter(is_approved=False):
            user.approve_user(request.user)
            try:
                EmailService.send_approval_email(user)
                count += 1
            except Exception as e:
                self.message_user(
                    request, 
                    f"Failed to send email to {user.email}: {str(e)}", 
                    level='WARNING'
                )
        
        self.message_user(request, f"{count} users approved and notified.")
    approve_users.short_description = "Approve selected users"
    
    def unlock_accounts(self, request, queryset):
        """Unlock locked accounts."""
        count = queryset.filter(account_locked=True).count()
        queryset.update(
            account_locked=False,
            account_locked_time=None,
            login_attempts=0
        )
        self.message_user(request, f"{count} accounts unlocked.")
    unlock_accounts.short_description = "Unlock selected accounts"
    
    def verify_emails(self, request, queryset):
        """Mark emails as verified."""
        count = 0
        for user in queryset.filter(email_verified=False):
            user.verify_email()
            count += 1
        self.message_user(request, f"{count} emails marked as verified.")
    verify_emails.short_description = "Verify email addresses"
    
    def resend_verification_emails(self, request, queryset):
        """Resend email verification."""
        count = 0
        for user in queryset.filter(email_verified=False):
            token = user.generate_email_verification_token()
            try:
                EmailService.send_email_verification_email(user, token)
                count += 1
            except Exception as e:
                self.message_user(
                    request,
                    f"Failed to send to {user.email}: {str(e)}",
                    level='WARNING'
                )
        self.message_user(request, f"{count} verification emails sent.")
    resend_verification_emails.short_description = "Resend verification emails"
    
    def bulk_approve_users(self, request, queryset):
        """Bulk approve multiple users."""
        count = 0
        errors = []
        
        for user in queryset.filter(is_approved=False):
            try:
                user.approve_user(request.user)
                EmailService.send_approval_email(user)
                count += 1
            except Exception as e:
                errors.append(f"Failed to approve {user.email}: {str(e)}")
        
        if errors:
            for error in errors:
                self.message_user(request, error, level='WARNING')
        
        self.message_user(request, f"{count} users approved successfully.")

    bulk_approve_users.short_description = "Bulk approve selected users"

    def export_user_data(self, request, queryset):
        """Export user data for compliance reporting."""
        import csv
        from django.http import HttpResponse
        
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="user_export.csv"'
        
        writer = csv.writer(response)
        writer.writerow(['Email', 'Role', 'Date Joined', 'Approved', 'Email Verified', 'Last Login'])
        
        for user in queryset:
            writer.writerow([
                user.email,
                user.get_role_display(),
                user.date_joined.strftime('%Y-%m-%d'),
                'Yes' if user.is_approved else 'No',
                'Yes' if user.email_verified else 'No',
                user.last_login.strftime('%Y-%m-%d') if user.last_login else 'Never'
            ])
        
        return response

    export_user_data.short_description = "Export user data (CSV)"
        
    def reset_login_attempts(self, request, queryset):
        """Reset login attempts."""
        count = queryset.filter(login_attempts__gt=0).count()
        queryset.update(login_attempts=0)
        self.message_user(request, f"Reset login attempts for {count} users.")
    reset_login_attempts.short_description = "Reset login attempts"


@admin.register(TwoFactorDevice)
class TwoFactorDeviceAdmin(admin.ModelAdmin):
    """Admin for 2FA devices."""
    list_display = ('user', 'confirmed', 'created_at', 'last_used_at')
    list_filter = ('confirmed', 'created_at')
    search_fields = ('user__username', 'user__email')
    readonly_fields = ('secret_key', 'created_at', 'last_used_at')
    
    def has_add_permission(self, request):
        return False  # Don't allow manual creation


@admin.register(PatientProfile)
class PatientProfileAdmin(admin.ModelAdmin):
    """Admin for patient profiles."""
    list_display = (
        'user', 'identity_verified', 'verification_status',
        'medication_consent', 'vitals_consent', 'research_consent'
    )
    list_filter = (
        'identity_verified', 'medication_adherence_monitoring_consent',
        'vitals_monitoring_consent', 'research_participation_consent'
    )
    search_fields = ('user__username', 'user__email', 'user__first_name', 'user__last_name')
    readonly_fields = (
        'identity_verification_date', 'first_login_date',
        'medication_adherence_consent_date', 'vitals_monitoring_consent_date',
        'research_consent_date'
    )
    
    fieldsets = (
        ('User', {'fields': ('user',)}),
        ('Medical Information', {
            'fields': (
                'medical_id', 'blood_type', 'allergies',
                'primary_condition', 'condition_diagnosis_date'
            )
        }),
        ('Emergency Contact', {
            'fields': (
                'emergency_contact_name', 'emergency_contact_phone',
                'emergency_contact_relationship'
            )
        }),
        ('Identity Verification', {
            'fields': (
                'identity_verified', 'identity_verification_method',
                'identity_verification_date', 'first_login_date',
                'verification_deadline_notified'
            )
        }),
        ('Consent Management', {
            'fields': (
                'medication_adherence_monitoring_consent',
                'medication_adherence_consent_date',
                'vitals_monitoring_consent',
                'vitals_monitoring_consent_date',
                'research_participation_consent',
                'research_consent_date'
            )
        }),
    )
    
    def verification_status(self, obj):
        """Display verification status with color coding."""
        if obj.identity_verified:
            return format_html(
                '<span style="color: green;">✓ Verified</span>'
            )
        elif obj.first_login_date:
            days_left = obj.days_until_verification_required()
            if days_left is None:
                return 'N/A'
            elif days_left == 0:
                return format_html(
                    '<span style="color: red;">⚠ Expired</span>'
                )
            elif days_left <= 7:
                return format_html(
                    '<span style="color: orange;">⚠ {} days left</span>',
                    days_left
                )
            else:
                return f'{days_left} days left'
        return 'Not logged in'
    verification_status.short_description = 'Verification Status'
    
    def medication_consent(self, obj):
        return '✓' if obj.medication_adherence_monitoring_consent else '✗'
    medication_consent.short_description = 'Med Consent'
    
    def vitals_consent(self, obj):
        return '✓' if obj.vitals_monitoring_consent else '✗'
    vitals_consent.short_description = 'Vitals Consent'
    
    def research_consent(self, obj):
        return '✓' if obj.research_participation_consent else '✗'
    research_consent.short_description = 'Research Consent'


@admin.register(ProviderProfile)
class ProviderProfileAdmin(admin.ModelAdmin):
    """Admin for provider profiles."""
    list_display = (
        'user', 'medical_license_number', 'npi_number', 
        'specialty', 'accepting_new_patients'
    )
    list_filter = ('accepting_new_patients', 'telemedicine_available', 'specialty')
    search_fields = (
        'user__username', 'user__email', 'medical_license_number',
        'npi_number', 'practice_name'
    )


@admin.register(PharmcoProfile)
class PharmcoProfileAdmin(admin.ModelAdmin):
    """Admin for pharmaceutical company profiles."""
    list_display = (
        'user', 'company_name', 'role_at_company',
        'regulatory_id', 'primary_research_focus'
    )
    search_fields = (
        'user__username', 'user__email', 'company_name',
        'regulatory_id'
    )


@admin.register(CaregiverProfile)
class CaregiverProfileAdmin(admin.ModelAdmin):
    """Admin for caregiver profiles."""
    list_display = (
        'user', 'relationship_to_patient', 'caregiver_type',
        'access_level', 'is_primary_caregiver'
    )
    list_filter = ('caregiver_type', 'access_level', 'is_primary_caregiver')
    search_fields = (
        'user__username', 'user__email', 'patient_email',
        'relationship_to_patient'
    )


@admin.register(ResearcherProfile)
class ResearcherProfileAdmin(admin.ModelAdmin):
    """Admin for researcher profiles."""
    list_display = (
        'user', 'institution_name', 'primary_research_area',
        'institutional_verification', 'years_experience'
    )
    list_filter = ('institutional_verification', 'primary_research_area', 'institution_type')
    search_fields = (
        'user__username', 'user__email', 'institution_name',
        'research_id'
    )
    
    actions = ['verify_researchers', 'unverify_researchers']
    
    def verify_researchers(self, request, queryset):
        """Verify selected researchers."""
        count = queryset.update(institutional_verification=True)
        self.message_user(request, f"{count} researchers verified.")
    verify_researchers.short_description = "Verify selected researchers"
    
    def unverify_researchers(self, request, queryset):
        """Unverify selected researchers."""
        count = queryset.update(institutional_verification=False)
        self.message_user(request, f"{count} researchers unverified.")
    unverify_researchers.short_description = "Unverify selected researchers"


@admin.register(ComplianceProfile)
class ComplianceProfileAdmin(admin.ModelAdmin):
    """Admin for compliance officer profiles."""
    list_display = (
        'user', 'organization_name', 'compliance_role', 
        'can_view_all_phi', 'can_generate_reports'
    )
    list_filter = ('compliance_role', 'can_view_all_phi', 'can_generate_reports', 'can_audit_access_logs')
    search_fields = (
        'user__username', 'user__email', 'organization_name',
        'license_number'
    )
    readonly_fields = ('user',)


@admin.register(CaregiverRequest)
class CaregiverRequestAdmin(admin.ModelAdmin):
    """Admin for caregiver requests."""
    list_display = (
        'caregiver', 'patient', 'relationship',
        'status', 'requested_at', 'responded_at'
    )
    list_filter = ('status', 'requested_at', 'patient_notified')
    search_fields = (
        'caregiver__username', 'caregiver__email',
        'patient__username', 'patient__email',
        'relationship'
    )
    readonly_fields = (
        'requested_at', 'responded_at', 'patient_notified',
        'reminder_sent'
    )
    
    actions = ['send_reminders', 'mark_expired']
    
    def send_reminders(self, request, queryset):
        """Send reminder notifications."""
        from .utils import EmailService
        
        count = 0
        for req in queryset.filter(status='PENDING', reminder_sent=False):
            try:
                EmailService.send_caregiver_request_notification(
                    req.patient, req.caregiver
                )
                req.reminder_sent = True
                req.save(update_fields=['reminder_sent'])
                count += 1
            except Exception as e:
                self.message_user(
                    request,
                    f"Failed to send reminder for {req.id}: {str(e)}",
                    level='WARNING'
                )
        
        self.message_user(request, f"{count} reminders sent.")
    send_reminders.short_description = "Send reminder notifications"
    
    def mark_expired(self, request, queryset):
        """Mark old requests as expired."""
        cutoff = timezone.now() - timezone.timedelta(days=30)
        count = queryset.filter(
            status='PENDING',
            requested_at__lt=cutoff
        ).update(status='EXPIRED')
        
        self.message_user(request, f"{count} requests marked as expired.")
    mark_expired.short_description = "Mark as expired"


@admin.register(EmergencyAccess)
class EmergencyAccessAdmin(admin.ModelAdmin):
    """Admin for emergency access records."""
    list_display = (
        'requester', 'patient_identifier_masked', 'reason',
        'requested_at', 'status_display', 'reviewed'
    )
    list_filter = (
        'reason', 'reviewed', 'access_justified',
        'requested_at', 'notifications_sent'
    )
    search_fields = (
        'requester__username', 'requester__email',
        'detailed_reason', 'review_notes'
    )
    readonly_fields = (
        'requester', 'requested_at', 'accessed_at',
        'ip_address', 'user_agent', 'duration',
        'reviewed_at', 'reviewed_by', 'notifications_sent'
    )
    
    fieldsets = (
        ('Request Information', {
            'fields': (
                'requester', 'patient_identifier', 'reason',
                'detailed_reason'
            )
        }),
        ('Access Details', {
            'fields': (
                'requested_at', 'accessed_at', 'access_ended_at',
                'phi_accessed', 'duration'
            )
        }),
        ('Technical Information', {
            'fields': ('ip_address', 'user_agent')
        }),
        ('Review', {
            'fields': (
                'reviewed', 'reviewed_by', 'reviewed_at',
                'review_notes', 'access_justified'
            )
        }),
        ('Notifications', {
            'fields': ('notifications_sent',)
        }),
    )
    
    actions = ['send_review_reminders', 'mark_reviewed']
    
    def patient_identifier_masked(self, obj):
        """Mask patient identifier for privacy."""
        if obj.patient_identifier:
            # Show only first and last characters
            if len(obj.patient_identifier) > 4:
                return f"{obj.patient_identifier[:2]}***{obj.patient_identifier[-2:]}"
            return "***"
        return "N/A"
    patient_identifier_masked.short_description = 'Patient ID'
    
    def status_display(self, obj):
        """Display access status with color coding."""
        if obj.is_active:
            return format_html(
                '<span style="color: red;">● Active</span>'
            )
        elif obj.reviewed:
            if obj.access_justified:
                return format_html(
                    '<span style="color: green;">✓ Justified</span>'
                )
            else:
                return format_html(
                    '<span style="color: orange;">✗ Not Justified</span>'
                )
        else:
            return format_html(
                '<span style="color: blue;">⧗ Pending Review</span>'
            )
    status_display.short_description = 'Status'
    
    def send_review_reminders(self, request, queryset):
        """Send reminders for unreviewed access."""
        from .utils import EmailService
        
        count = 0
        for access in queryset.filter(reviewed=False):
            try:
                EmailService.send_emergency_access_notification(access)
                count += 1
            except Exception as e:
                self.message_user(
                    request,
                    f"Failed to send reminder for {access.id}: {str(e)}",
                    level='WARNING'
                )
        
        self.message_user(request, f"{count} review reminders sent.")
    send_review_reminders.short_description = "Send review reminders"
    
    def mark_reviewed(self, request, queryset):
        """Quick mark as reviewed (neutral)."""
        count = queryset.filter(reviewed=False).update(
            reviewed=True,
            reviewed_by=request.user,
            reviewed_at=timezone.now(),
            review_notes="Marked as reviewed via admin action"
        )
        
        self.message_user(request, f"{count} access records marked as reviewed.")
    mark_reviewed.short_description = "Mark as reviewed"


@admin.register(ConsentRecord)
class ConsentRecordAdmin(admin.ModelAdmin):
    """Admin for consent records."""
    list_display = (
        'user', 'consent_type', 'consented',
        'signature_timestamp', 'revoked', 'ip_display'
    )
    list_filter = (
        'consent_type', 'consented', 'revoked',
        'signature_timestamp'
    )
    search_fields = (
        'user__username', 'user__email',
        'document_version', 'revocation_reason'
    )
    readonly_fields = (
        'user', 'consent_type', 'consented',
        'signature_timestamp', 'signature_ip',
        'signature_user_agent', 'document_version',
        'document_checksum'
    )
    
    fieldsets = (
        ('Consent Information', {
            'fields': (
                'user', 'consent_type', 'consented',
                'signature_timestamp'
            )
        }),
        ('Document Information', {
            'fields': ('document_version', 'document_checksum')
        }),
        ('Technical Details', {
            'fields': ('signature_ip', 'signature_user_agent')
        }),
        ('Revocation', {
            'fields': ('revoked', 'revoked_at', 'revocation_reason')
        }),
    )
    
    def has_add_permission(self, request):
        """Prevent manual creation of consent records."""
        return False
    
    def has_change_permission(self, request, obj=None):
        """Prevent editing of consent records."""
        return False
    
    def has_delete_permission(self, request, obj=None):
        """Only superusers can delete consent records."""
        return request.user.is_superuser
    
    def ip_display(self, obj):
        """Display IP address."""
        return obj.signature_ip or 'N/A'
    ip_display.short_description = 'IP Address'


@admin.register(HIPAADocument)
class HIPAADocumentAdmin(admin.ModelAdmin):
    """Admin for HIPAA documents."""
    list_display = (
        'title', 'document_type', 'version',
        'effective_date', 'active', 'created_at'
    )
    list_filter = (
        'document_type', 'active', 'effective_date',
        'created_at'
    )
    search_fields = ('title', 'content', 'version')
    readonly_fields = ('created_at', 'created_by', 'checksum')
    
    fieldsets = (
        ('Document Information', {
            'fields': (
                'title', 'document_type', 'version',
                'content'
            )
        }),
        ('Validity', {
            'fields': (
                'effective_date', 'expiration_date', 'active'
            )
        }),
        ('Metadata', {
            'fields': ('created_at', 'created_by', 'checksum')
        }),
    )
    
    actions = ['activate_documents', 'deactivate_documents']
    
    def save_model(self, request, obj, form, change):
        """Set created_by on new documents."""
        if not change:
            obj.created_by = request.user
        
        # Deactivate other versions if this is being activated
        if obj.active:
            HIPAADocument.objects.filter(
                document_type=obj.document_type,
                active=True
            ).exclude(pk=obj.pk).update(active=False)
        
        super().save_model(request, obj, form, change)
    
    def activate_documents(self, request, queryset):
        """Activate selected documents."""
        for doc in queryset:
            # Deactivate others of same type
            HIPAADocument.objects.filter(
                document_type=doc.document_type,
                active=True
            ).exclude(pk=doc.pk).update(active=False)
            
            doc.active = True
            doc.save()
        
        self.message_user(
            request,
            f"{queryset.count()} documents activated."
        )
    activate_documents.short_description = "Activate selected documents"
    
    def deactivate_documents(self, request, queryset):
        """Deactivate selected documents."""
        count = queryset.update(active=False)
        self.message_user(request, f"{count} documents deactivated.")
    deactivate_documents.short_description = "Deactivate selected documents"


@admin.register(PatientAuthorizedCaregiver)
class PatientAuthorizedCaregiverAdmin(admin.ModelAdmin):
    """Admin for patient-caregiver authorizations."""
    list_display = (
        'patient', 'caregiver', 'access_level',
        'authorized_at', 'expires_at', 'is_active'
    )
    list_filter = ('access_level', 'authorized_at')
    search_fields = (
        'patient__user__username', 'patient__user__email',
        'caregiver__username', 'caregiver__email'
    )
    readonly_fields = ('authorized_at', 'authorized_by')
    
    def is_active(self, obj):
        """Check if authorization is active."""
        if obj.expires_at:
            return obj.expires_at > timezone.now()
        return True
    is_active.boolean = True
    is_active.short_description = 'Active'


@admin.register(TemporaryRegistrationData)
class TemporaryRegistrationDataAdmin(admin.ModelAdmin):
    """Admin for temporary registration data."""
    list_display = ('user', 'created_at', 'data_summary')
    list_filter = ('created_at', 'user__role')
    search_fields = ('user__email', 'user__username')
    readonly_fields = ('user', 'data', 'created_at')
    
    def data_summary(self, obj):
        """Show summary of stored data."""
        data = obj.data
        if isinstance(data, dict):
            keys = list(data.keys())[:3]  # Show first 3 keys
            summary = ', '.join(keys)
            if len(data) > 3:
                summary += '...'
            return summary
        return str(data)[:50]
    
    data_summary.short_description = 'Data Summary'
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False


# Customize admin site header and title
admin.site.site_header = "Klararety Health Platform Administration"
admin.site.site_title = "Klararety Admin"
admin.site.index_title = "Healthcare System Management"
