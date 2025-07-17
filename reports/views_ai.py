import logging
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.viewsets import ViewSet
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from .models import Report
from .services.ai_integration import AIIntegrationService
from .permissions import IsApprovedUser, CanAccessAnalytics

logger = logging.getLogger('hipaa_audit')

class AIAnalysisViewSet(ViewSet):
    """API endpoint for AI Analysis operations."""
    permission_classes = [IsAuthenticated, IsApprovedUser, CanAccessAnalytics]
    
    @swagger_auto_schema(
        method='post',
        operation_description="Analyze data with Claude AI",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['data_type', 'time_period', 'reason'],
            properties={
                'data_type': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Type of data to analyze',
                    enum=['patient_adherence', 'patient_vitals', 'provider_performance', 
                          'population_health', 'medication_efficacy', 'telemedicine_usage']
                ),
                'time_period': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Time period for analysis',
                    enum=['7d', '30d', '90d', '6m', '1y']
                ),
                'reason': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Reason for analysis (HIPAA compliance)'
                ),
                'custom_prompt': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Custom prompt for Claude (optional)'
                ),
                'system_prompt': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Custom system prompt for Claude (optional)'
                )
            }
        ),
        responses={
            200: "AI Analysis results",
            400: "Invalid request",
            403: "Permission denied",
            500: "Analysis failed"
        }
    )
    @action(detail=False, methods=['post'])
    def analyze_data(self, request):
        """Analyze data with Claude AI."""
        # Get request parameters
        data_type = request.data.get('data_type')
        time_period = request.data.get('time_period', '30d')
        reason = request.data.get('reason')
        custom_prompt = request.data.get('custom_prompt')
        system_prompt = request.data.get('system_prompt')
        
        # Validate required parameters
        if not data_type:
            return Response(
                {"detail": "Data type is required."},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        if not reason:
            return Response(
                {"detail": "Analysis reason is required for HIPAA compliance."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Log the analysis request
        logger.info(
            f"AI_ANALYSIS_REQUEST: User {request.user.username} (ID: {request.user.id}) "
            f"requested analysis of {data_type} data with reason: {reason}"
        )
        
        try:
            # Create AI integration service
            ai_service = AIIntegrationService()
            
            # Analyze data with Claude
            analysis_results = ai_service.analyze_with_claude(
                data_type=data_type,
                time_period=time_period,
                user=request.user,
                prompt=custom_prompt,
                system_prompt=system_prompt
            )
            
            return Response(analysis_results)
            
        except PermissionError as e:
            return Response(
                {"detail": str(e)},
                status=status.HTTP_403_FORBIDDEN
            )
        except ValueError as e:
            return Response(
                {"detail": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(
                f"AI_ANALYSIS_ERROR: User {request.user.username} (ID: {request.user.id}) "
                f"encountered error during analysis: {str(e)}"
            )
            return Response(
                {"detail": f"Analysis failed: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @swagger_auto_schema(
        method='post',
        operation_description="Analyze a report with Claude AI",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['report_id', 'reason'],
            properties={
                'report_id': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='ID of the report to analyze'
                ),
                'reason': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Reason for analysis (HIPAA compliance)'
                ),
                'custom_prompt': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Custom prompt for Claude (optional)'
                ),
                'system_prompt': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Custom system prompt for Claude (optional)'
                )
            }
        ),
        responses={
            200: "AI Analysis results",
            400: "Invalid request",
            403: "Permission denied",
            404: "Report not found",
            500: "Analysis failed"
        }
    )
    @action(detail=False, methods=['post'])
    def analyze_report(self, request):
        """Analyze an existing report with Claude AI."""
        # Get request parameters
        report_id = request.data.get('report_id')
        reason = request.data.get('reason')
        custom_prompt = request.data.get('custom_prompt')
        system_prompt = request.data.get('system_prompt')
        
        # Validate required parameters
        if not report_id:
            return Response(
                {"detail": "Report ID is required."},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        if not reason:
            return Response(
                {"detail": "Analysis reason is required for HIPAA compliance."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Log the analysis request
        logger.info(
            f"REPORT_AI_ANALYSIS_REQUEST: User {request.user.username} (ID: {request.user.id}) "
            f"requested analysis of report {report_id} with reason: {reason}"
        )
        
        try:
            # Verify report exists
            try:
                report = Report.objects.get(id=report_id)
            except Report.DoesNotExist:
                return Response(
                    {"detail": f"Report with ID {report_id} not found."},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Create AI integration service
            ai_service = AIIntegrationService()
            
            # Analyze report with Claude
            analysis_results = ai_service.analyze_report_with_claude(
                report_id=report_id,
                user=request.user,
                prompt=custom_prompt,
                system_prompt=system_prompt
            )
            
            return Response(analysis_results)
            
        except PermissionError as e:
            return Response(
                {"detail": str(e)},
                status=status.HTTP_403_FORBIDDEN
            )
        except ValueError as e:
            return Response(
                {"detail": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(
                f"REPORT_AI_ANALYSIS_ERROR: User {request.user.username} (ID: {request.user.id}) "
                f"encountered error during report analysis: {str(e)}"
            )
            return Response(
                {"detail": f"Analysis failed: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
