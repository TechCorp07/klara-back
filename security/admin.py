# security/admin.py
from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils.safestring import mark_safe
from .models import (
    SecurityThreat, VulnerabilityAssessment, Vulnerability,
    SecurityIncident, NetworkMonitor, FileIntegrityMonitor,
    SecurityConfiguration, ComplianceReport
)


@admin.register(SecurityThreat)
class SecurityThreatAdmin(admin.ModelAdmin):
    list_display = [
        'title', 'threat_type', 'severity_badge', 'status_badge', 
        'affected_user', 'detection_time', 'assigned_to'
    ]
    list_filter = [
        'threat_type', 'severity', 'status', 'detection_source', 'detection_time'
    ]
    search_fields = ['title', 'description', 'source_ip', 'target_ip']
    readonly_fields = ['id', 'detection_time', 'first_seen', 'last_seen']
    date_hierarchy = 'detection_time'
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('id', 'threat_type', 'severity', 'status', 'title', 'description')
        }),
        ('Detection Details', {
            'fields': ('detection_time', 'first_seen', 'last_seen', 'detection_source')
        }),
        ('Network Information', {
            'fields': ('source_ip', 'target_ip'),
            'classes': ('collapse',)
        }),
        ('Assignment', {
            'fields': ('affected_user', 'assigned_to')
        }),
        ('Resolution', {
            'fields': ('resolved_at', 'resolved_by', 'resolution_notes'),
            'classes': ('collapse',)
        }),
        ('Technical Data', {
            'fields': ('threat_indicators', 'response_actions'),
            'classes': ('collapse',)
        })
    )
    
    def severity_badge(self, obj):
        colors = {
            'critical': '#dc3545',
            'high': '#fd7e14', 
            'medium': '#ffc107',
            'low': '#198754',
            'info': '#0dcaf0'
        }
        color = colors.get(obj.severity, '#6c757d')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 2px 6px; border-radius: 3px; font-size: 11px;">{}</span>',
            color, obj.get_severity_display()
        )
    severity_badge.short_description = 'Severity'
    
    def status_badge(self, obj):
        colors = {
            'detected': '#dc3545',
            'investigating': '#fd7e14',
            'contained': '#ffc107',
            'mitigated': '#198754',
            'resolved': '#198754',
            'false_positive': '#6c757d'
        }
        color = colors.get(obj.status, '#6c757d')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 2px 6px; border-radius: 3px; font-size: 11px;">{}</span>',
            color, obj.get_status_display()
        )
    status_badge.short_description = 'Status'


@admin.register(VulnerabilityAssessment)
class VulnerabilityAssessmentAdmin(admin.ModelAdmin):
    list_display = [
        'target', 'scan_type', 'status_badge', 'total_vulnerabilities',
        'critical_count', 'high_count', 'started_at', 'duration_formatted'
    ]
    list_filter = ['scan_type', 'status', 'scanner_tool', 'started_at']
    search_fields = ['target', 'scanner_tool']
    readonly_fields = [
        'id', 'started_at', 'completed_at', 'duration_seconds', 
        'total_vulnerabilities', 'critical_count', 'high_count',
        'medium_count', 'low_count', 'info_count'
    ]
    date_hierarchy = 'started_at'
    
    def status_badge(self, obj):
        colors = {
            'scheduled': '#6c757d',
            'running': '#fd7e14',
            'completed': '#198754',
            'failed': '#dc3545',
            'cancelled': '#6c757d'
        }
        color = colors.get(obj.status, '#6c757d')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 2px 6px; border-radius: 3px; font-size: 11px;">{}</span>',
            color, obj.get_status_display()
        )
    status_badge.short_description = 'Status'
    
    def duration_formatted(self, obj):
        if obj.duration_seconds:
            hours = obj.duration_seconds // 3600
            minutes = (obj.duration_seconds % 3600) // 60
            seconds = obj.duration_seconds % 60
            
            if hours > 0:
                return f"{hours}h {minutes}m {seconds}s"
            elif minutes > 0:
                return f"{minutes}m {seconds}s"
            else:
                return f"{seconds}s"
        return "-"
    duration_formatted.short_description = 'Duration'


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = [
        'title', 'severity_badge', 'status_badge', 'cvss_score',
        'affected_component', 'cve_id', 'first_discovered', 'assigned_to'
    ]
    list_filter = ['severity', 'status', 'assessment__scan_type', 'first_discovered']
    search_fields = ['title', 'description', 'cve_id', 'cwe_id', 'affected_component']
    readonly_fields = ['id', 'first_discovered', 'last_seen']
    date_hierarchy = 'first_discovered'
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('title', 'description', 'severity', 'status')
        }),
        ('Vulnerability Identifiers', {
            'fields': ('cve_id', 'cwe_id', 'cvss_score', 'cvss_vector')
        }),
        ('Location', {
            'fields': ('assessment', 'affected_component', 'location')
        }),
        ('Remediation', {
            'fields': ('remediation_advice', 'assigned_to', 'fixed_at')
        }),
        ('Discovery', {
            'fields': ('first_discovered', 'last_seen'),
            'classes': ('collapse',)
        }),
        ('Technical Details', {
            'fields': ('proof_of_concept', 'references'),
            'classes': ('collapse',)
        })
    )
    
    def severity_badge(self, obj):
        colors = {
            'critical': '#dc3545',
            'high': '#fd7e14',
            'medium': '#ffc107', 
            'low': '#198754',
            'info': '#0dcaf0'
        }
        color = colors.get(obj.severity, '#6c757d')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 2px 6px; border-radius: 3px; font-size: 11px;">{}</span>',
            color, obj.get_severity_display()
        )
    severity_badge.short_description = 'Severity'
    
    def status_badge(self, obj):
        colors = {
            'open': '#dc3545',
            'in_progress': '#fd7e14',
            'fixed': '#198754',
            'accepted_risk': '#ffc107',
            'false_positive': '#6c757d',
            'wont_fix': '#6c757d',
            'duplicate': '#6c757d'
        }
        color = colors.get(obj.status, '#6c757d')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 2px 6px; border-radius: 3px; font-size: 11px;">{}</span>',
            color, obj.get_status_display()
        )
    status_badge.short_description = 'Status'


@admin.register(SecurityIncident)
class SecurityIncidentAdmin(admin.ModelAdmin):
    list_display = [
        'incident_id', 'title', 'incident_type', 'priority_badge',
        'status_badge', 'reported_at', 'assigned_to'
    ]
    list_filter = ['incident_type', 'priority', 'status', 'reported_at']
    search_fields = ['incident_id', 'title', 'description']
    readonly_fields = ['id', 'incident_id', 'reported_at', 'closed_at']
    date_hierarchy = 'reported_at'
    
    fieldsets = (
        ('Incident Information', {
            'fields': ('incident_id', 'incident_type', 'priority', 'status', 'title', 'description')
        }),
        ('Timeline', {
            'fields': ('discovered_at', 'reported_at', 'closed_at')
        }),
        ('Assignment', {
            'fields': ('reported_by', 'assigned_to', 'team_members')
        }),
        ('Impact', {
            'fields': ('affected_systems', 'affected_users', 'impact_assessment')
        }),
        ('Response Actions', {
            'fields': ('containment_actions', 'eradication_actions', 'recovery_actions'),
            'classes': ('collapse',)
        }),
        ('Analysis', {
            'fields': ('lessons_learned',),
            'classes': ('collapse',)
        }),
        ('Related Items', {
            'fields': ('related_threats', 'related_vulnerabilities'),
            'classes': ('collapse',)
        })
    )
    
    filter_horizontal = ['team_members', 'affected_users', 'related_threats', 'related_vulnerabilities']
    
    def priority_badge(self, obj):
        colors = {
            'critical': '#dc3545',
            'high': '#fd7e14',
            'medium': '#ffc107',
            'low': '#198754'
        }
        color = colors.get(obj.priority, '#6c757d')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 2px 6px; border-radius: 3px; font-size: 11px;">{}</span>',
            color, obj.get_priority_display()
        )
    priority_badge.short_description = 'Priority'
    
    def status_badge(self, obj):
        colors = {
            'reported': '#dc3545',
            'acknowledged': '#fd7e14',
            'investigating': '#ffc107',
            'containment': '#fd7e14',
            'eradication': '#ffc107',
            'recovery': '#17a2b8',
            'post_incident': '#28a745',
            'closed': '#198754'
        }
        color = colors.get(obj.status, '#6c757d')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 2px 6px; border-radius: 3px; font-size: 11px;">{}</span>',
            color, obj.get_status_display()
        )
    status_badge.short_description = 'Status'


@admin.register(NetworkMonitor)
class NetworkMonitorAdmin(admin.ModelAdmin):
    list_display = [
        'alert_type', 'severity_badge', 'source_ip', 'destination_ip',
        'timestamp', 'is_false_positive'
    ]
    list_filter = ['alert_type', 'severity', 'timestamp', 'is_false_positive']
    search_fields = ['source_ip', 'destination_ip', 'description']
    readonly_fields = ['id', 'timestamp']
    date_hierarchy = 'timestamp'
    
    def severity_badge(self, obj):
        colors = {
            'critical': '#dc3545',
            'high': '#fd7e14',
            'medium': '#ffc107',
            'low': '#198754'
        }
        color = colors.get(obj.severity, '#6c757d')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 2px 6px; border-radius: 3px; font-size: 11px;">{}</span>',
            color, obj.get_severity_display()
        )
    severity_badge.short_description = 'Severity'


@admin.register(FileIntegrityMonitor)
class FileIntegrityMonitorAdmin(admin.ModelAdmin):
    list_display = [
        'file_name', 'change_type_badge', 'timestamp', 'is_critical_file',
        'is_authorized_change', 'user_context'
    ]
    list_filter = ['change_type', 'timestamp', 'is_critical_file', 'is_authorized_change']
    search_fields = ['file_path', 'user_context', 'process_name']
    readonly_fields = ['id', 'timestamp']
    date_hierarchy = 'timestamp'
    
    def file_name(self, obj):
        import os
        return os.path.basename(obj.file_path)
    file_name.short_description = 'File Name'
    
    def change_type_badge(self, obj):
        colors = {
            'created': '#198754',
            'modified': '#ffc107',
            'deleted': '#dc3545',
            'moved': '#17a2b8',
            'permissions_changed': '#fd7e14',
            'ownership_changed': '#fd7e14'
        }
        color = colors.get(obj.change_type, '#6c757d')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 2px 6px; border-radius: 3px; font-size: 11px;">{}</span>',
            color, obj.get_change_type_display()
        )
    change_type_badge.short_description = 'Change Type'


@admin.register(SecurityConfiguration)
class SecurityConfigurationAdmin(admin.ModelAdmin):
    list_display = ['name', 'config_type', 'is_active', 'created_by', 'updated_at']
    list_filter = ['config_type', 'is_active', 'created_at']
    search_fields = ['name', 'description']
    readonly_fields = ['id', 'created_at', 'updated_at']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'config_type', 'description', 'is_active')
        }),
        ('Configuration', {
            'fields': ('configuration',)
        }),
        ('Metadata', {
            'fields': ('created_by', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )


@admin.register(ComplianceReport)
class ComplianceReportAdmin(admin.ModelAdmin):
    list_display = [
        'report_type', 'status_badge', 'compliance_score_badge',
        'period_start', 'period_end', 'generated_at', 'generated_by'
    ]
    list_filter = ['report_type', 'status', 'generated_at']
    search_fields = ['report_type']
    readonly_fields = [
        'id', 'generated_at', 'compliance_score', 'total_controls',
        'passed_controls', 'failed_controls'
    ]
    date_hierarchy = 'generated_at'
    
    def status_badge(self, obj):
        colors = {
            'generating': '#fd7e14',
            'completed': '#198754',
            'failed': '#dc3545'
        }
        color = colors.get(obj.status, '#6c757d')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 2px 6px; border-radius: 3px; font-size: 11px;">{}</span>',
            color, obj.get_status_display()
        )
    status_badge.short_description = 'Status'
    
    def compliance_score_badge(self, obj):
        if obj.compliance_score is None:
            return '-'
        
        if obj.compliance_score >= 90:
            color = '#198754'
        elif obj.compliance_score >= 70:
            color = '#ffc107'
        else:
            color = '#dc3545'
        
        return format_html(
            '<span style="background-color: {}; color: white; padding: 2px 6px; border-radius: 3px; font-size: 11px;">{:.1f}%</span>',
            color, obj.compliance_score
        )
    compliance_score_badge.short_description = 'Compliance Score'


# Customize admin site header
admin.site.site_header = "Klararety Security Administration"
admin.site.site_title = "Security Admin"
admin.site.index_title = "Security Management"