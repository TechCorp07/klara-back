import os
import logging
import json
import requests
import anthropic
from django.conf import settings
from django.utils import timezone
from django.db.models import Q
from django.contrib.auth import get_user_model

from ..models import DataExport, Report, ReportConfiguration
from .analytics import AnalyticsService

User = get_user_model()
logger = logging.getLogger('hipaa_audit')

class AIIntegrationService:
    """Service for integrating with external AI systems like Claude."""
    
    def __init__(self):
        """Initialize with API keys from settings."""
        self.claude_api_key = getattr(settings, 'CLAUDE_API_KEY', os.environ.get('CLAUDE_API_KEY'))
        self.claude_model = getattr(settings, 'CLAUDE_MODEL', 'claude-3-opus-20240229')
        self.analytics_service = AnalyticsService()
    
    def analyze_with_claude(self, data_type, time_period, user, prompt=None, system_prompt=None):
        """
        Analyze data with Claude API.
        
        Args:
            data_type: Type of data to analyze
            time_period: Time period string (e.g., '30d', '90d')
            user: User requesting the analysis
            prompt: Custom prompt to send to Claude (if None, will use default)
            system_prompt: Custom system prompt (if None, will use default)
            
        Returns:
            dict: Analysis results from Claude
        """
        if not self.claude_api_key:
            raise ValueError("Claude API key not configured. Please set CLAUDE_API_KEY in settings or environment.")
        
        # Log the beginning of AI analysis
        logger.info(
            f"AI_ANALYSIS_STARTED: User {user.username} (ID: {user.id}) "
            f"started analyzing {data_type} data with Claude"
        )
        
        try:
            # Get data for AI analysis
            data, record_count = self.analytics_service.prepare_ai_data(
                data_type=data_type,
                time_period=time_period,
                user=user
            )
            
            # Log data export
            export_record = DataExport.objects.create(
                user=user,
                export_format='JSON',
                data_type=f"AI_Analysis_{data_type}",
                parameters={"time_period": time_period},
                record_count=record_count,
                export_reason="Data analysis with Claude AI",
                file_size=len(json.dumps(data)),
            )
            
            # Create default prompts if not provided
            if system_prompt is None:
                system_prompt = self._get_default_system_prompt(data_type)
            
            if prompt is None:
                prompt = self._get_default_prompt(data_type, data)
            else:
                # If custom prompt provided, add data to it
                prompt = f"{prompt}\n\nData: {json.dumps(data)}"
            
            # Call Claude API
            client = anthropic.Anthropic(api_key=self.claude_api_key)
            message = client.messages.create(
                model=self.claude_model,
                max_tokens=4000,
                system=system_prompt,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            
            # Extract and return analysis results
            analysis_results = {
                'analysis': message.content,
                'data_type': data_type,
                'time_period': time_period,
                'analyzed_at': timezone.now().isoformat(),
                'model_used': self.claude_model
            }
            
            # Log successful analysis
            logger.info(
                f"AI_ANALYSIS_COMPLETED: User {user.username} (ID: {user.id}) "
                f"completed analyzing {data_type} data with Claude - Export ID: {export_record.id}"
            )
            
            return analysis_results
            
        except Exception as e:
            # Log error
            logger.error(
                f"AI_ANALYSIS_FAILED: User {user.username} (ID: {user.id}) "
                f"failed to analyze {data_type} data with Claude: {str(e)}"
            )
            raise
    
    def analyze_report_with_claude(self, report_id, user, prompt=None, system_prompt=None):
        """
        Analyze an existing report with Claude API.
        
        Args:
            report_id: ID of the report to analyze
            user: User requesting the analysis
            prompt: Custom prompt to send to Claude (if None, will use default)
            system_prompt: Custom system prompt (if None, will use default)
            
        Returns:
            dict: Analysis results from Claude
        """
        if not self.claude_api_key:
            raise ValueError("Claude API key not configured. Please set CLAUDE_API_KEY in settings or environment.")
        
        # Get the report
        try:
            report = Report.objects.get(id=report_id)
        except Report.DoesNotExist:
            raise ValueError(f"Report with ID {report_id} not found")
        
        # Check if the report is completed
        if report.status != 'COMPLETED':
            raise ValueError(f"Report with ID {report_id} is not completed")
        
        # Check access permission
        if not self._check_report_access(report, user):
            raise PermissionError("You don't have permission to analyze this report")
        
        # Log the beginning of AI analysis
        logger.info(
            f"REPORT_AI_ANALYSIS_STARTED: User {user.username} (ID: {user.id}) "
            f"started analyzing report {report.report_id} with Claude"
        )
        
        try:
            # Get report data
            report_data = report.results_json
            
            # Create default prompts if not provided
            if system_prompt is None:
                system_prompt = self._get_default_system_prompt(report.configuration.report_type)
            
            if prompt is None:
                prompt = self._get_default_report_prompt(report)
            else:
                # If custom prompt provided, add report data to it
                prompt = f"{prompt}\n\nReport Data: {json.dumps(report_data)}"
            
            # Call Claude API
            client = anthropic.Anthropic(api_key=self.claude_api_key)
            message = client.messages.create(
                model=self.claude_model,
                max_tokens=4000,
                system=system_prompt,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            
            # Extract and return analysis results
            analysis_results = {
                'analysis': message.content,
                'report_id': str(report.report_id),
                'report_type': report.configuration.report_type,
                'analyzed_at': timezone.now().isoformat(),
                'model_used': self.claude_model
            }
            
            # Log successful analysis
            logger.info(
                f"REPORT_AI_ANALYSIS_COMPLETED: User {user.username} (ID: {user.id}) "
                f"completed analyzing report {report.report_id} with Claude"
            )
            
            # Update report access count
            report.accessed_count += 1
            report.last_accessed = timezone.now()
            report.save(update_fields=['accessed_count', 'last_accessed'])
            
            return analysis_results
            
        except Exception as e:
            # Log error
            logger.error(
                f"REPORT_AI_ANALYSIS_FAILED: User {user.username} (ID: {user.id}) "
                f"failed to analyze report {report.report_id} with Claude: {str(e)}"
            )
            raise
    
    def _check_report_access(self, report, user):
        """Check if user has access to the report."""
        # Admins and compliance officers can access all reports
        if user.is_staff or user.role in ['admin', 'compliance']:
            return True
        
        # Creator can access
        if report.created_by == user:
            return True
        
        # Check configuration access
        config = report.configuration
        
        # Public configurations are accessible
        if config.is_public:
            return True
        
        # Check if user role is in allowed roles
        if user.role in config.allowed_roles:
            return True
        
        # Otherwise, no access
        return False
    
    def _get_default_system_prompt(self, data_type):
        """Get a default system prompt based on data type."""
        system_prompts = {
            'patient_adherence': "You are a healthcare analytics expert specializing in medication adherence analysis. Your task is to analyze medication adherence data and provide insights that could help improve patient outcomes and treatment effectiveness.",
            
            'patient_vitals': "You are a healthcare analytics expert specializing in patient vital signs analysis. Your task is to analyze vitals data trends and identify patterns that could indicate health changes or areas for intervention.",
            
            'provider_performance': "You are a healthcare analytics expert specializing in provider performance analysis. Your task is to analyze provider metrics and identify trends, strengths, and areas for improvement while maintaining a balanced and constructive perspective.",
            
            'population_health': "You are a healthcare analytics expert specializing in population health analysis. Your task is to analyze demographic and health data to identify trends and suggest potential public health initiatives or targeted interventions.",
            
            'medication_efficacy': "You are a pharmaceutical analytics expert specializing in medication efficacy analysis. Your task is to analyze medication outcomes data to identify patterns in effectiveness, side effects, and adherence that could inform treatment protocols.",
            
            'telemedicine_usage': "You are a healthcare technology expert specializing in telemedicine analytics. Your task is to analyze telemedicine usage data to identify trends, opportunities, and areas for improvement in virtual care delivery."
        }
        
        # Default to a generic prompt if data type not recognized
        return system_prompts.get(
            data_type, 
            "You are a healthcare analytics expert. Your task is to analyze healthcare data and provide clear, actionable insights based on the patterns you identify. Focus on the most significant findings and provide recommendations when appropriate."
        )
    
    def _get_default_prompt(self, data_type, data):
        """Get a default prompt based on data type and include the data."""
        prompts = {
            'patient_adherence': "Please analyze this medication adherence data and provide insights on: \n1. Overall adherence trends \n2. Factors affecting adherence \n3. Medications with highest and lowest adherence \n4. Recommendations for improving adherence",
            
            'patient_vitals': "Please analyze this patient vitals data and provide insights on: \n1. Key trends in vital measurements \n2. Any concerning patterns or outliers \n3. Correlations between different vitals \n4. Recommendations for monitoring priorities",
            
            'provider_performance': "Please analyze this provider performance data and provide insights on: \n1. Key performance trends \n2. Comparison across providers or specialties \n3. Factors affecting performance metrics \n4. Balanced recommendations for improvement",
            
            'population_health': "Please analyze this population health data and provide insights on: \n1. Key demographic health trends \n2. Health disparities or high-risk groups \n3. Condition prevalence patterns \n4. Recommendations for targeted health initiatives",
            
            'medication_efficacy': "Please analyze this medication efficacy data and provide insights on: \n1. Overall effectiveness patterns \n2. Side effect correlations \n3. Patient response variations \n4. Recommendations for optimizing medication use",
            
            'telemedicine_usage': "Please analyze this telemedicine usage data and provide insights on: \n1. Usage trends and patterns \n2. Factors affecting completion rates \n3. Patient satisfaction correlations \n4. Recommendations for improving telemedicine services"
        }
        
        # Default to a generic prompt if data type not recognized
        base_prompt = prompts.get(
            data_type, 
            "Please analyze this healthcare data and provide your key insights and recommendations."
        )
        
        # Add the data to the prompt
        return f"{base_prompt}\n\nData: {json.dumps(data)}"
    
    def _get_default_report_prompt(self, report):
        """Get a default prompt for analyzing a report."""
        report_type = report.configuration.report_type
        report_name = report.configuration.name
        
        base_prompt = f"Please analyze this {report_type} report titled '{report_name}' and provide your key insights, observations, and recommendations. Focus on the most significant findings and provide actionable recommendations based on the data."
        
        # Add the report data to the prompt
        return f"{base_prompt}\n\nReport Data: {json.dumps(report.results_json)}"
