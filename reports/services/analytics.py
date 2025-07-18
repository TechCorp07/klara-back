import logging
from datetime import datetime, timedelta
from django.utils import timezone
from django.db.models import Count, Avg, Sum, F, Q, ExpressionWrapper, FloatField, DateTimeField, Min, Max
from django.db.models.functions import TruncDay, TruncWeek, TruncMonth, Cast
from django.contrib.auth import get_user_model

User = get_user_model()
logger = logging.getLogger('hipaa_audit')

class AnalyticsService:
    """Service for analytics operations and dashboard data."""
    
    def get_widget_data(self, data_source, configuration, user):
        """
        Get data for a dashboard widget.
        
        Args:
            data_source: String identifying the data source
            configuration: Widget configuration dictionary
            user: User requesting the data
            
        Returns:
            dict: Widget data
        """
        # Choose data retrieval method based on data source
        if data_source == 'adherence_metrics':
            return self._get_adherence_widget_data(configuration, user)
        elif data_source == 'vitals_trends':
            return self._get_vitals_widget_data(configuration, user)
        elif data_source == 'provider_performance':
            return self._get_provider_performance_widget_data(configuration, user)
        elif data_source == 'population_health':
            return self._get_population_health_widget_data(configuration, user)
        elif data_source == 'medication_efficacy':
            return self._get_medication_efficacy_widget_data(configuration, user)
        elif data_source == 'telemedicine_usage':
            return self._get_telemedicine_widget_data(configuration, user)
        elif data_source == 'user_activity':
            return self._get_user_activity_widget_data(configuration, user)
        elif data_source == 'phi_access':
            return self._get_phi_access_widget_data(configuration, user)
        elif data_source == 'consent_activity':
            return self._get_consent_activity_widget_data(configuration, user)
        else:
            raise ValueError(f"Unsupported data source: {data_source}")
    
    def calculate_metric(self, metric, parameters, user):
        """
        Calculate a specific analytics metric with the given parameters.
        
        Args:
            metric: AnalyticsMetric instance
            parameters: Dictionary of calculation parameters
            user: User requesting the calculation
            
        Returns:
            dict: Calculation results
        """
        # Log the metric calculation
        logger.info(
            f"METRIC_CALCULATION_STARTED: User {user.username} (ID: {user.id}) "
            f"started calculating metric {metric.id} ({metric.name})"
        )
        
        # Perform the calculation based on the metric's data source
        if metric.data_source == 'adherence_metrics':
            return self._calculate_adherence_metric(metric, parameters, user)
        elif metric.data_source == 'vitals_trends':
            return self._calculate_vitals_metric(metric, parameters, user)
        elif metric.data_source == 'provider_performance':
            return self._calculate_provider_metric(metric, parameters, user)
        elif metric.data_source == 'population_health':
            return self._calculate_population_metric(metric, parameters, user)
        elif metric.data_source == 'medication_efficacy':
            return self._calculate_medication_metric(metric, parameters, user)
        elif metric.data_source == 'telemedicine_usage':
            return self._calculate_telemedicine_metric(metric, parameters, user)
        else:
            raise ValueError(f"Unsupported metric data source: {metric.data_source}")
    
    def get_adherence_metrics(self, time_period='30d', condition=None, medication=None, user=None):
        """
        Get medication adherence metrics.
        
        Args:
            time_period: Time period string (e.g., '30d', '90d')
            condition: Optional condition filter
            medication: Optional medication filter
            user: User requesting the data
            
        Returns:
            dict: Adherence metrics
        """
        # Calculate start date
        start_date = self._calculate_start_date(time_period)
        
        # Import models
        from medication.models import AdherenceRecord, Prescription
        
        # Base query
        adherence_records = AdherenceRecord.objects.filter(
            recorded_date__gte=start_date
        )
        
        # Apply role-based filters
        adherence_records = self._apply_adherence_filters(adherence_records, user, condition, medication)
        
        # Calculate overall metrics
        overall_metrics = adherence_records.aggregate(
            total_records=Count('id'),
            total_patients=Count('patient', distinct=True),
            total_medications=Count('prescription__medication', distinct=True),
            avg_adherence_rate=Avg('adherence_rate')
        )
        
        # Group by date
        if time_period in ['7d', '30d']:
            # Daily grouping for shorter periods
            adherence_by_date = list(
                adherence_records.annotate(
                    date=TruncDay('recorded_date')
                ).values('date').annotate(
                    count=Count('id'),
                    avg_rate=Avg('adherence_rate')
                ).order_by('date')
            )
        else:
            # Weekly grouping for longer periods
            adherence_by_date = list(
                adherence_records.annotate(
                    date=TruncWeek('recorded_date')
                ).values('date').annotate(
                    count=Count('id'),
                    avg_rate=Avg('adherence_rate')
                ).order_by('date')
            )
        
        # Group by medication
        adherence_by_medication = list(
            adherence_records.values(
                'prescription__medication__name'
            ).annotate(
                count=Count('id'),
                avg_rate=Avg('adherence_rate')
            ).order_by('-count')[:10]  # Top 10 medications
        )
        
        return {
            'overall_metrics': overall_metrics,
            'adherence_by_date': adherence_by_date,
            'adherence_by_medication': adherence_by_medication,
            'time_period': time_period,
            'condition_filter': condition,
            'medication_filter': medication
        }
    
    def get_vitals_trends(self, time_period='30d', metric=None, patient_id=None, user=None):
        """
        Get patient vitals trends.
        
        Args:
            time_period: Time period string (e.g., '30d', '90d')
            metric: Optional metric type filter
            patient_id: Optional patient ID filter
            user: User requesting the data
            
        Returns:
            dict: Vitals trends
        """
        # Calculate start date
        start_date = self._calculate_start_date(time_period)
        
        # Import models
        from healthcare.models import Vital
        
        # Base query
        vitals = Vital.objects.filter(
            recorded_at__gte=start_date
        )
        
        # Apply role-based filters
        vitals = self._apply_vitals_filters(vitals, user, metric, patient_id)
        
        # Calculate overall metrics
        overall_metrics = vitals.aggregate(
            total_records=Count('id'),
            total_patients=Count('patient', distinct=True)
        )
        
        # Add metric-specific aggregates if a single metric is selected
        if metric:
            overall_metrics.update(
                vitals.aggregate(
                    avg_value=Avg('value'),
                    min_value=Min('value'),
                    max_value=Max('value')
                )
            )
        
        # Group by date
        if time_period in ['7d', '30d']:
            # Daily grouping for shorter periods
            vitals_by_date = list(
                vitals.annotate(
                    date=TruncDay('recorded_at')
                ).values('date', 'metric_type').annotate(
                    count=Count('id'),
                    avg_value=Avg('value')
                ).order_by('date', 'metric_type')
            )
        else:
            # Weekly grouping for longer periods
            vitals_by_date = list(
                vitals.annotate(
                    date=TruncWeek('recorded_at')
                ).values('date', 'metric_type').annotate(
                    count=Count('id'),
                    avg_value=Avg('value')
                ).order_by('date', 'metric_type')
            )
        
        # Group by metric type if no specific metric was selected
        metrics_summary = []
        if not metric:
            metrics_summary = list(
                vitals.values('metric_type').annotate(
                    count=Count('id'),
                    avg_value=Avg('value'),
                    min_value=Min('value'),
                    max_value=Max('value')
                ).order_by('metric_type')
            )
        
        return {
            'overall_metrics': overall_metrics,
            'vitals_by_date': vitals_by_date,
            'metrics_summary': metrics_summary,
            'time_period': time_period,
            'metric_filter': metric,
            'patient_id': patient_id
        }
    
    def get_provider_performance(self, provider_id=None, metric=None, time_period='30d', user=None):
        """
        Get provider performance metrics.
        
        Args:
            provider_id: Optional provider ID filter
            metric: Optional performance metric filter
            time_period: Time period string (e.g., '30d', '90d')
            user: User requesting the data
            
        Returns:
            dict: Provider performance metrics
        """
        # Check access permissions
        if user.role not in ['admin', 'provider', 'compliance'] and not user.is_staff:
            # For providers, only allow their own performance data
            if user.role == 'provider':
                provider_id = user.id
            else:
                raise PermissionError("You don't have permission to access provider performance data.")
        
        # Calculate start date
        start_date = self._calculate_start_date(time_period)
        
        # Import models
        from telemedicine.models import VideoConsultation, Appointment
        
        # Base queries
        consultations = VideoConsultation.objects.filter(
            scheduled_time__gte=start_date,
            status='COMPLETED'
        )
        
        appointments = Appointment.objects.filter(
            scheduled_time__gte=start_date
        )
        
        # Apply provider filter if specified
        if provider_id:
            consultations = consultations.filter(provider_id=provider_id)
            appointments = appointments.filter(provider_id=provider_id)
        
        # Calculate overall metrics
        overall_metrics = consultations.aggregate(
            total_consultations=Count('id'),
            avg_duration=Avg('duration'),
            total_providers=Count('provider', distinct=True),
            total_patients=Count('patient', distinct=True)
        )
        
        # Add appointment metrics
        appointment_metrics = appointments.aggregate(
            total_appointments=Count('id'),
            completed_appointments=Count('id', filter=Q(status='COMPLETED')),
            cancelled_appointments=Count('id', filter=Q(status='CANCELLED')),
            no_show_appointments=Count('id', filter=Q(status='NO_SHOW'))
        )
        
        overall_metrics.update(appointment_metrics)
        
        # Calculate completion rate
        if overall_metrics['total_appointments'] > 0:
            overall_metrics['completion_rate'] = (overall_metrics['completed_appointments'] / 
                                             overall_metrics['total_appointments'] * 100)
        else:
            overall_metrics['completion_rate'] = 0
        
        # Provider-level metrics
        provider_metrics = list(
            consultations.values(
                'provider_id',
                'provider__user__username',
                'provider__user__first_name',
                'provider__user__last_name',
                'provider__specialty'
            ).annotate(
                consultation_count=Count('id'),
                avg_duration=Avg('duration'),
                patient_count=Count('patient', distinct=True),
                avg_rating=Avg('rating')
            ).order_by('-consultation_count')
        )
        
        # Activity by date
        if time_period in ['7d', '30d']:
            # Daily grouping for shorter periods
            activity_by_date = list(
                consultations.annotate(
                    date=TruncDay('scheduled_time')
                ).values('date').annotate(
                    count=Count('id'),
                    avg_duration=Avg('duration'),
                    avg_rating=Avg('rating')
                ).order_by('date')
            )
        else:
            # Weekly grouping for longer periods
            activity_by_date = list(
                consultations.annotate(
                    date=TruncWeek('scheduled_time')
                ).values('date').annotate(
                    count=Count('id'),
                    avg_duration=Avg('duration'),
                    avg_rating=Avg('rating')
                ).order_by('date')
            )
        
        return {
            'overall_metrics': overall_metrics,
            'provider_metrics': provider_metrics,
            'activity_by_date': activity_by_date,
            'time_period': time_period,
            'provider_id': provider_id,
            'metric_filter': metric
        }
    
    def get_population_health(self, condition=None, demographic=None, metric=None, user=None):
        """
        Get population health metrics.
        
        Args:
            condition: Optional condition filter
            demographic: Optional demographic factor filter
            metric: Optional health metric filter
            user: User requesting the data
            
        Returns:
            dict: Population health metrics
        """
        # Check access permissions
        if user.role not in ['admin', 'provider', 'compliance', 'researcher'] and not user.is_staff:
            if user.role == 'researcher' and hasattr(user, 'researcher_profile'):
                if not user.researcher_profile.is_verified:
                    raise PermissionError("Only verified researchers can access population health data.")
            else:
                raise PermissionError("You don't have permission to access population health data.")
        
        # Import models
        from users.models import PatientProfile, PatientCondition
        
        # Base queries
        patients = PatientProfile.objects.all()
        
        # Apply condition filter if specified
        if condition:
            patient_conditions = PatientCondition.objects.filter(
                condition_name__icontains=condition
            )
            patients = patients.filter(id__in=patient_conditions.values('patient_id'))
        
        # Calculate overall metrics
        overall_metrics = {
            'total_patients': patients.count(),
        }
        
        # Age distribution
        from django.db.models.functions import ExtractYear
        current_year = timezone.now().year
        
        age_groups = [
            {'name': '18-30', 'min': 18, 'max': 30},
            {'name': '31-45', 'min': 31, 'max': 45},
            {'name': '46-60', 'min': 46, 'max': 60},
            {'name': '61-75', 'min': 61, 'max': 75},
            {'name': '75+', 'min': 76, 'max': 120}
        ]
        
        age_distribution = []
        for group in age_groups:
            min_birth_year = current_year - group['max']
            max_birth_year = current_year - group['min']
            
            count = patients.filter(
                user__date_of_birth__year__gte=min_birth_year,
                user__date_of_birth__year__lte=max_birth_year
            ).count()
            
            age_distribution.append({
                'age_group': group['name'],
                'count': count,
                'percentage': (count / overall_metrics['total_patients'] * 100) if overall_metrics['total_patients'] > 0 else 0
            })
        
        # Gender distribution
        gender_distribution = list(
            patients.values(
                'user__profile__gender'
            ).annotate(
                count=Count('id')
            ).order_by('user__profile__gender')
        )
        
        for item in gender_distribution:
            item['percentage'] = (item['count'] / overall_metrics['total_patients'] * 100) if overall_metrics['total_patients'] > 0 else 0
        
        # Condition distribution
        condition_distribution = []
        if not condition:
            condition_distribution = list(
                PatientCondition.objects.values(
                    'condition_name'
                ).annotate(
                    count=Count('id')
                ).order_by('-count')[:10]  # Top 10 conditions
            )
            
            for item in condition_distribution:
                item['percentage'] = (item['count'] / overall_metrics['total_patients'] * 100) if overall_metrics['total_patients'] > 0 else 0
        
        return {
            'overall_metrics': overall_metrics,
            'age_distribution': age_distribution,
            'gender_distribution': gender_distribution,
            'condition_distribution': condition_distribution,
            'condition_filter': condition,
            'demographic_filter': demographic,
            'metric_filter': metric
        }
    
    def prepare_ai_data(self, data_type, time_period='30d', user=None):
        """
        Prepare data for AI analysis (Claude, ChatGPT, etc.).
        
        Args:
            data_type: Type of data to prepare
            time_period: Time period string (e.g., '30d', '90d')
            user: User requesting the data
            
        Returns:
            tuple: (data, record_count)
        """
        # Calculate start date
        start_date = self._calculate_start_date(time_period)
        
        # Check access permissions
        if user.role not in ['admin', 'provider', 'compliance', 'researcher'] and not user.is_staff:
            if user.role == 'researcher' and hasattr(user, 'researcher_profile'):
                if not user.researcher_profile.is_verified:
                    raise PermissionError("Only verified researchers can prepare data for AI analysis.")
            else:
                raise PermissionError("You don't have permission to prepare data for AI analysis.")
        
        # Prepare data based on type
        if data_type == 'patient_conditions':
            return self._prepare_patient_conditions_data(start_date, user)
        elif data_type == 'medication_adherence':
            return self._prepare_medication_adherence_data(start_date, user)
        elif data_type == 'vitals_trends':
            return self._prepare_vitals_trends_data(start_date, user)
        elif data_type == 'telemedicine_usage':
            return self._prepare_telemedicine_usage_data(start_date, user)
        elif data_type == 'provider_performance':
            return self._prepare_provider_performance_data(start_date, user)
        else:
            raise ValueError(f"Unsupported data type: {data_type}")
    
    def _prepare_patient_conditions_data(self, start_date, user):
        """Prepare patient conditions data for AI analysis."""
        from users.models import PatientCondition
        
        # Get conditions data
        conditions = PatientCondition.objects.filter(
            created_at__gte=start_date
        )
        
        # Apply anonymization for non-admin/non-compliance users
        if user.role not in ['admin', 'compliance'] and not user.is_staff:
            # For researchers, only include research-consented patients
            if user.role == 'researcher':
                conditions = conditions.filter(patient__user__research_consent=True)
            
            # Anonymize data
            conditions_data = list(
                conditions.values(
                    'condition_name',
                    'condition_code',
                    'status',
                    'is_primary'
                ).annotate(
                    patient_count=Count('patient', distinct=True),
                    avg_age=Avg('patient__user__age')  # This would be calculated in a real implementation
                )
            )
        else:
            # Full data for admins and compliance officers
            conditions_data = list(
                conditions.values(
                    'condition_name',
                    'condition_code',
                    'status',
                    'is_primary',
                    'diagnosis_date',
                    'patient__user__age',  # This would be calculated in a real implementation
                    'patient__user__gender'
                )
            )
        
        # Add metadata
        ai_data = {
            'data_type': 'patient_conditions',
            'generated_at': timezone.now().isoformat(),
            'record_count': len(conditions_data),
            'data': conditions_data
        }
        
        return ai_data, len(conditions_data)
    
    def _prepare_medication_adherence_data(self, start_date, user):
        """Prepare medication adherence data for AI analysis."""
        from medication.models import AdherenceRecord
        
        # Get adherence data
        adherence_records = AdherenceRecord.objects.filter(
            recorded_date__gte=start_date
        )
        
        # Apply filters based on user role
        adherence_records = self._apply_adherence_filters(adherence_records, user)
        
        # Prepare data
        adherence_data = list(
            adherence_records.values(
                'prescription__medication__name',
                'adherence_rate',
                'recorded_date'
            ).annotate(
                patient_count=Count('patient', distinct=True)
            )
        )
        
        # Add aggregated metrics
        from django.db.models.functions import TruncWeek
        
        adherence_by_week = list(
            adherence_records.annotate(
                week=TruncWeek('recorded_date')
            ).values('week').annotate(
                avg_rate=Avg('adherence_rate'),
                record_count=Count('id')
            ).order_by('week')
        )
        
        adherence_by_medication = list(
            adherence_records.values(
                'prescription__medication__name'
            ).annotate(
                avg_rate=Avg('adherence_rate'),
                record_count=Count('id')
            ).order_by('-record_count')
        )
        
        # Add metadata
        ai_data = {
            'data_type': 'medication_adherence',
            'generated_at': timezone.now().isoformat(),
            'record_count': len(adherence_data),
            'data': adherence_data,
            'adherence_by_week': adherence_by_week,
            'adherence_by_medication': adherence_by_medication
        }
        
        return ai_data, len(adherence_data)
    
    def _prepare_vitals_trends_data(self, start_date, user):
        """Prepare vitals trends data for AI analysis."""
        from healthcare.models import Vital
        
        # Get vitals data
        vitals = Vital.objects.filter(
            recorded_at__gte=start_date
        )
        
        # Apply filters based on user role
        vitals = self._apply_vitals_filters(vitals, user)
        
        # Prepare data
        vitals_data = list(
            vitals.values(
                'metric_type',
                'value',
                'recorded_at'
            )
        )
        
        # Add aggregated metrics
        from django.db.models.functions import TruncWeek
        
        vitals_by_week = list(
            vitals.annotate(
                week=TruncWeek('recorded_at')
            ).values('week', 'metric_type').annotate(
                avg_value=Avg('value'),
                min_value=Min('value'),
                max_value=Max('value'),
                record_count=Count('id')
            ).order_by('week', 'metric_type')
        )
        
        vitals_summary = list(
            vitals.values(
                'metric_type'
            ).annotate(
                avg_value=Avg('value'),
                min_value=Min('value'),
                max_value=Max('value'),
                record_count=Count('id')
            ).order_by('metric_type')
        )
        
        # Add metadata
        ai_data = {
            'data_type': 'vitals_trends',
            'generated_at': timezone.now().isoformat(),
            'record_count': len(vitals_data),
            'data': vitals_data,
            'vitals_by_week': vitals_by_week,
            'vitals_summary': vitals_summary
        }
        
        return ai_data, len(vitals_data)
    
    def _prepare_telemedicine_usage_data(self, start_date, user):
        """Prepare telemedicine usage data for AI analysis."""
        from telemedicine.models import VideoConsultation
        
        # Get consultation data
        consultations = VideoConsultation.objects.filter(
            scheduled_time__gte=start_date
        )
        
        # Apply filters based on user role
        if user.role == 'provider':
            consultations = consultations.filter(provider_id=user.id)
        elif user.role == 'patient':
            if hasattr(user, 'patient_profile'):
                consultations = consultations.filter(patient=user.patient_profile)
            else:
                return {'data': [], 'record_count': 0}, 0
        
        # Anonymize data for researchers
        if user.role == 'researcher':
            consultations = consultations.filter(patient__user__research_consent=True)
            
            # Prepare anonymized data
            usage_data = list(
                consultations.values(
                    'status',
                    'scheduled_time',
                    'duration',
                    'rating'
                ).annotate(
                    provider_specialty=F('provider__specialty')
                )
            )
        else:
            # Prepare data with more details
            usage_data = list(
                consultations.values(
                    'status',
                    'scheduled_time',
                    'duration',
                    'rating',
                    'provider__specialty',
                    'consultation_type'
                )
            )
        
        # Add aggregated metrics
        from django.db.models.functions import TruncWeek
        
        usage_by_week = list(
            consultations.annotate(
                week=TruncWeek('scheduled_time')
            ).values('week').annotate(
                completed=Count('id', filter=Q(status='COMPLETED')),
                cancelled=Count('id', filter=Q(status='CANCELLED')),
                no_show=Count('id', filter=Q(status='NO_SHOW')),
                avg_duration=Avg('duration', filter=Q(status='COMPLETED')),
                avg_rating=Avg('rating', filter=Q(rating__isnull=False))
            ).order_by('week')
        )
        
        usage_by_specialty = list(
            consultations.values(
                'provider__specialty'
            ).annotate(
                count=Count('id'),
                completed=Count('id', filter=Q(status='COMPLETED')),
                avg_duration=Avg('duration', filter=Q(status='COMPLETED')),
                avg_rating=Avg('rating', filter=Q(rating__isnull=False))
            ).order_by('-count')
        )
        
        # Add metadata
        ai_data = {
            'data_type': 'telemedicine_usage',
            'generated_at': timezone.now().isoformat(),
            'record_count': len(usage_data),
            'data': usage_data,
            'usage_by_week': usage_by_week,
            'usage_by_specialty': usage_by_specialty
        }
        
        return ai_data, len(usage_data)
    
    def _prepare_provider_performance_data(self, start_date, user):
        """Prepare provider performance data for AI analysis."""
        # Check access permissions - restricted to admins, compliance, and providers (their own)
        if user.role not in ['admin', 'compliance'] and not user.is_staff:
            if user.role != 'provider':
                raise PermissionError("You don't have permission to access provider performance data.")
        
        from telemedicine.models import VideoConsultation
        
        # Get consultation data
        consultations = VideoConsultation.objects.filter(
            scheduled_time__gte=start_date,
            status='COMPLETED'
        )
        
        # Filter to provider's own data if not admin/compliance
        if user.role == 'provider':
            consultations = consultations.filter(provider_id=user.id)
        
        # Prepare data
        if user.role in ['admin', 'compliance'] or user.is_staff:
            # Detailed data for admins and compliance
            performance_data = list(
                consultations.values(
                    'provider_id',
                    'provider__user__username',
                    'provider__specialty',
                    'scheduled_time',
                    'duration',
                    'rating'
                )
            )
        else:
            # Limited data for providers (own performance only)
            performance_data = list(
                consultations.values(
                    'scheduled_time',
                    'duration',
                    'rating',
                    'consultation_type'
                )
            )
        
        # Add aggregated metrics
        provider_metrics = list(
            consultations.values(
                'provider_id',
                'provider__user__username',
                'provider__specialty'
            ).annotate(
                consultation_count=Count('id'),
                avg_duration=Avg('duration'),
                patient_count=Count('patient', distinct=True),
                avg_rating=Avg('rating', filter=Q(rating__isnull=False))
            ).order_by('-consultation_count')
        )
        
        from django.db.models.functions import TruncWeek
        
        performance_by_week = list(
            consultations.annotate(
                week=TruncWeek('scheduled_time')
            ).values('week').annotate(
                count=Count('id'),
                avg_duration=Avg('duration'),
                avg_rating=Avg('rating', filter=Q(rating__isnull=False))
            ).order_by('week')
        )
        
        # Add metadata
        ai_data = {
            'data_type': 'provider_performance',
            'generated_at': timezone.now().isoformat(),
            'record_count': len(performance_data),
            'data': performance_data,
            'provider_metrics': provider_metrics,
            'performance_by_week': performance_by_week
        }
        
        return ai_data, len(performance_data)
    
    def _get_adherence_widget_data(self, configuration, user):
        """Get adherence metrics data for a dashboard widget."""
        # Get parameters from configuration
        time_period = configuration.get('time_period', '30d')
        medication = configuration.get('medication')
        condition = configuration.get('condition')
        
        # Get adherence metrics
        return self.get_adherence_metrics(time_period, condition, medication, user)
    
    def _get_vitals_widget_data(self, configuration, user):
        """Get vitals trends data for a dashboard widget."""
        # Get parameters from configuration
        time_period = configuration.get('time_period', '30d')
        metric = configuration.get('metric')
        patient_id = configuration.get('patient_id')
        
        # Get vitals trends
        return self.get_vitals_trends(time_period, metric, patient_id, user)
    
    def _get_provider_performance_widget_data(self, configuration, user):
        """Get provider performance data for a dashboard widget."""
        # Get parameters from configuration
        time_period = configuration.get('time_period', '30d')
        provider_id = configuration.get('provider_id')
        metric = configuration.get('metric')
        
        # Get provider performance metrics
        return self.get_provider_performance(provider_id, metric, time_period, user)
    
    def _get_population_health_widget_data(self, configuration, user):
        """Get population health data for a dashboard widget."""
        # Get parameters from configuration
        condition = configuration.get('condition')
        demographic = configuration.get('demographic')
        metric = configuration.get('metric')
        
        # Get population health metrics
        return self.get_population_health(condition, demographic, metric, user)
    
    def _get_medication_efficacy_widget_data(self, configuration, user):
        """Get medication efficacy data for a dashboard widget."""
        # Get parameters from configuration
        medication_id = configuration.get('medication_id')
        condition_id = configuration.get('condition_id')
        time_period = configuration.get('time_period', '90d')
        
        # Check access permissions
        if user.role not in ['admin', 'provider', 'pharmco', 'researcher'] and not user.is_staff:
            if user.role == 'researcher' and hasattr(user, 'researcher_profile'):
                if not user.researcher_profile.is_verified:
                    raise PermissionError("Only verified researchers can access medication efficacy data.")
            elif user.role != 'pharmco':
                raise PermissionError("You don't have permission to access medication efficacy data.")
        
        # Import necessary models
        from medication.models import Medication, Prescription, AdherenceRecord, SideEffect
        from users.models import PatientCondition
        
        # Calculate start date
        start_date = self._calculate_start_date(time_period)
        
        # Base queries
        if medication_id:
            try:
                medication = Medication.objects.get(id=medication_id)
                prescriptions = Prescription.objects.filter(
                    medication=medication,
                    prescribed_date__gte=start_date
                )
            except Medication.DoesNotExist:
                raise ValueError(f"Medication with ID {medication_id} not found.")
        else:
            prescriptions = Prescription.objects.filter(
                prescribed_date__gte=start_date
            )
        
        # Apply condition filter if specified
        if condition_id:
            try:
                condition = PatientCondition.objects.get(id=condition_id)
                prescriptions = prescriptions.filter(
                    patient__conditions=condition
                )
            except PatientCondition.DoesNotExist:
                raise ValueError(f"Condition with ID {condition_id} not found.")
        
        # Calculate efficacy metrics
        total_patients = prescriptions.values('patient').distinct().count()
        total_prescriptions = prescriptions.count()
        
        efficacy_metrics = {
            'total_patients': total_patients,
            'total_prescriptions': total_prescriptions,
        }
        
        # Calculate adherence metrics
        adherence_records = AdherenceRecord.objects.filter(
            prescription__in=prescriptions
        )
        
        if adherence_records.exists():
            efficacy_metrics['adherence'] = adherence_records.aggregate(
                avg_rate=Avg('adherence_rate'),
                total_records=Count('id')
            )
        
        # Calculate side effects
        side_effects = SideEffect.objects.filter(
            prescription__in=prescriptions
        )
        
        if side_effects.exists():
            efficacy_metrics['side_effects'] = {
                'total_reported': side_effects.count(),
                'patients_reporting': side_effects.values('patient').distinct().count(),
                'percent_patients_with_side_effects': (side_effects.values('patient').distinct().count() / total_patients * 100) if total_patients > 0 else 0
            }
            
            # Most common side effects
            common_effects = list(
                side_effects.values(
                    'effect_type'
                ).annotate(
                    count=Count('id')
                ).order_by('-count')[:10]  # Top 10 side effects
            )
            
            efficacy_metrics['side_effects']['common_effects'] = common_effects
        
        # Return the widget data
        return {
            'efficacy_metrics': efficacy_metrics,
            'medication_id': medication_id,
            'medication_name': medication.name if medication_id else None,
            'condition_id': condition_id,
            'condition_name': condition.condition_name if condition_id else None,
            'time_period': time_period
        }
    
    def _get_telemedicine_widget_data(self, configuration, user):
        """Get telemedicine usage data for a dashboard widget."""
        # Get parameters from configuration
        time_period = configuration.get('time_period', '30d')
        provider_id = configuration.get('provider_id')
        
        # Check access permissions
        if user.role not in ['admin', 'provider', 'compliance'] and not user.is_staff:
            if user.role == 'provider':
                provider_id = user.id
            elif user.role != 'pharmco':
                raise PermissionError("You don't have permission to access telemedicine usage data.")
        
        # Calculate start date
        start_date = self._calculate_start_date(time_period)
        
        # Import necessary models
        from telemedicine.models import VideoConsultation, Appointment
        
        # Base queries
        consultations = VideoConsultation.objects.filter(
            scheduled_time__gte=start_date
        )
        
        appointments = Appointment.objects.filter(
            scheduled_time__gte=start_date
        )
        
        # Apply provider filter if specified
        if provider_id:
            consultations = consultations.filter(provider_id=provider_id)
            appointments = appointments.filter(provider_id=provider_id)
        
        # Calculate usage metrics
        usage_metrics = consultations.aggregate(
            total_consultations=Count('id'),
            total_providers=Count('provider', distinct=True),
            total_patients=Count('patient', distinct=True),
            avg_duration=Avg('duration')
        )
        
        # Add appointment metrics
        appointment_metrics = appointments.aggregate(
            total_appointments=Count('id'),
            completed_appointments=Count('id', filter=Q(status='COMPLETED')),
            cancelled_appointments=Count('id', filter=Q(status='CANCELLED')),
            no_show_appointments=Count('id', filter=Q(status='NO_SHOW'))
        )
        
        usage_metrics.update(appointment_metrics)
        
        # Calculate completion rate
        if usage_metrics['total_appointments'] > 0:
            usage_metrics['completion_rate'] = (usage_metrics['completed_appointments'] / 
                                             usage_metrics['total_appointments'] * 100)
        else:
            usage_metrics['completion_rate'] = 0
        
        # Usage by status
        usage_by_status = list(
            consultations.values(
                'status'
            ).annotate(
                count=Count('id')
            ).order_by('status')
        )
        
        # Usage by date
        if time_period in ['7d', '30d']:
            # Daily grouping for shorter periods
            usage_by_date = list(
                consultations.annotate(
                    date=TruncDay('scheduled_time')
                ).values('date').annotate(
                    consultations=Count('id'),
                    completed=Count('id', filter=Q(status='COMPLETED')),
                    cancelled=Count('id', filter=Q(status='CANCELLED')),
                    avg_duration=Avg('duration', filter=Q(status='COMPLETED'))
                ).order_by('date')
            )
        else:
            # Weekly grouping for longer periods
            usage_by_date = list(
                consultations.annotate(
                    date=TruncWeek('scheduled_time')
                ).values('date').annotate(
                    consultations=Count('id'),
                    completed=Count('id', filter=Q(status='COMPLETED')),
                    cancelled=Count('id', filter=Q(status='CANCELLED')),
                    avg_duration=Avg('duration', filter=Q(status='COMPLETED'))
                ).order_by('date')
            )
        
        # Return the widget data
        return {
            'usage_metrics': usage_metrics,
            'usage_by_status': usage_by_status,
            'usage_by_date': usage_by_date,
            'time_period': time_period,
            'provider_id': provider_id
        }
    
    def _get_user_activity_widget_data(self, configuration, user):
        """Get user activity data for a dashboard widget."""
        # Check access permissions - only admins and compliance officers
        if user.role not in ['admin', 'compliance'] and not user.is_staff:
            raise PermissionError("Only administrators and compliance officers can access user activity data.")
        
        # Get parameters from configuration
        time_period = configuration.get('time_period', '30d')
        role_filter = configuration.get('role')
        
        # Calculate start date
        start_date = self._calculate_start_date(time_period)
        
        # Import necessary models
        from django.contrib.auth import get_user_model
        from audit.models import SecurityAuditLog
        User = get_user_model()
        
        # Get recently active users
        active_users = User.objects.filter(
            last_login__gte=start_date
        )
        
        # Apply role filter if specified
        if role_filter:
            active_users = active_users.filter(role=role_filter)
        
        # Get security audit logs
        security_logs = SecurityAuditLog.objects.filter(
            timestamp__gte=start_date
        )
        
        # Calculate user activity metrics
        user_metrics = {
            'total_users': User.objects.count(),
            'active_users': active_users.count(),
            'activity_percentage': (active_users.count() / User.objects.count() * 100) if User.objects.exists() else 0,
        }
        
        # Activity by role
        activity_by_role = list(
            active_users.values(
                'role'
            ).annotate(
                count=Count('id')
            ).order_by('-count')
        )
        
        for item in activity_by_role:
            total_in_role = User.objects.filter(role=item['role']).count()
            item['percentage'] = (item['count'] / total_in_role * 100) if total_in_role > 0 else 0
        
        # Activity by date
        if time_period in ['7d', '30d']:
            # Daily grouping for shorter periods
            from django.db.models.functions import TruncDay
            
            activity_by_date = list(
                security_logs.annotate(
                    date=TruncDay('timestamp')
                ).values('date').annotate(
                    login_count=Count('id', filter=Q(event_type='AUTH_SUCCESS')),
                    failed_login_count=Count('id', filter=Q(event_type='AUTH_FAILURE')),
                    unique_users=Count('user', distinct=True, filter=Q(event_type='AUTH_SUCCESS'))
                ).order_by('date')
            )
        else:
            # Weekly grouping for longer periods
            from django.db.models.functions import TruncWeek
            
            activity_by_date = list(
                security_logs.annotate(
                    date=TruncWeek('timestamp')
                ).values('date').annotate(
                    login_count=Count('id', filter=Q(event_type='AUTH_SUCCESS')),
                    failed_login_count=Count('id', filter=Q(event_type='AUTH_FAILURE')),
                    unique_users=Count('user', distinct=True, filter=Q(event_type='AUTH_SUCCESS'))
                ).order_by('date')
            )
        
        # Return the widget data
        return {
            'user_metrics': user_metrics,
            'activity_by_role': activity_by_role,
            'activity_by_date': activity_by_date,
            'time_period': time_period,
            'role_filter': role_filter
        }
    
    def _get_phi_access_widget_data(self, configuration, user):
        """Get PHI access data for a dashboard widget."""
        # Check access permissions - only admins and compliance officers
        if user.role not in ['admin', 'compliance'] and not user.is_staff:
            raise PermissionError("Only administrators and compliance officers can access PHI access data.")
        
        # Get parameters from configuration
        time_period = configuration.get('time_period', '30d')
        access_type = configuration.get('access_type')
        
        # Calculate start date
        start_date = self._calculate_start_date(time_period)
        
        # Import necessary models
        from audit.models import PHIAccessLog
        
        # Base query
        phi_access_logs = PHIAccessLog.objects.filter(
            access_time__gte=start_date
        )
        
        # Apply access type filter if specified
        if access_type:
            phi_access_logs = phi_access_logs.filter(access_type=access_type)
        
        # Calculate access metrics
        access_metrics = phi_access_logs.aggregate(
            total_accesses=Count('id'),
            unique_users=Count('user', distinct=True)
        )
        
        # Access by user role
        access_by_role = list(
            phi_access_logs.values(
                'user__role'
            ).annotate(
                count=Count('id'),
                unique_users=Count('user', distinct=True)
            ).order_by('-count')
        )
        
        # Access by access type
        access_by_type = list(
            phi_access_logs.values(
                'access_type'
            ).annotate(
                count=Count('id')
            ).order_by('-count')
        )
        
        # Access by date
        if time_period in ['7d', '30d']:
            # Daily grouping for shorter periods
            access_by_date = list(
                phi_access_logs.annotate(
                    date=TruncDay('access_time')
                ).values('date').annotate(
                    count=Count('id'),
                    unique_users=Count('user', distinct=True)
                ).order_by('date')
            )
        else:
            # Weekly grouping for longer periods
            access_by_date = list(
                phi_access_logs.annotate(
                    date=TruncWeek('access_time')
                ).values('date').annotate(
                    count=Count('id'),
                    unique_users=Count('user', distinct=True)
                ).order_by('date')
            )
        
        # Return the widget data
        return {
            'access_metrics': access_metrics,
            'access_by_role': access_by_role,
            'access_by_type': access_by_type,
            'access_by_date': access_by_date,
            'time_period': time_period,
            'access_type': access_type
        }
    
    def _get_consent_activity_widget_data(self, configuration, user):
        """Get consent activity data for a dashboard widget."""
        # Check access permissions - only admins and compliance officers
        if user.role not in ['admin', 'compliance'] and not user.is_staff:
            raise PermissionError("Only administrators and compliance officers can access consent activity data.")
        
        # Get parameters from configuration
        time_period = configuration.get('time_period', '30d')
        consent_type = configuration.get('consent_type')
        
        # Calculate start date
        start_date = self._calculate_start_date(time_period)
        
        # Import necessary models
        from users.models import ConsentRecord, User
        
        # Base query
        consent_logs = ConsentRecord.objects.filter(
            signature_timestamp__gte=start_date
        )
        
        # Apply consent type filter if specified
        if consent_type:
            consent_logs = consent_logs.filter(consent_type=consent_type)
        
        # Calculate consent metrics
        consent_metrics = consent_logs.aggregate(
            total_consent_changes=Count('id'),
            unique_users=Count('user', distinct=True)
        )
        
        # Add consent granted vs revoked metrics
        consent_metrics.update(
            consent_logs.aggregate(
                granted=Count('id', filter=Q(consented=True)),
                revoked=Count('id', filter=Q(consented=False))
            )
        )
        
        # Activity by consent type
        activity_by_type = list(
            consent_logs.values(
                'consent_type'
            ).annotate(
                total=Count('id'),
                granted=Count('id', filter=Q(consented=True)),
                revoked=Count('id', filter=Q(consented=False))
            ).order_by('consent_type')
        )
        
        # Activity by date
        if time_period in ['7d', '30d']:
            # Daily grouping for shorter periods
            activity_by_date = list(
                consent_logs.annotate(
                    date=TruncDay('timestamp')
                ).values('date').annotate(
                    total=Count('id'),
                    granted=Count('id', filter=Q(consented=True)),
                    revoked=Count('id', filter=Q(consented=False))
                ).order_by('date')
            )
        else:
            # Weekly grouping for longer periods
            activity_by_date = list(
                consent_logs.annotate(
                    date=TruncWeek('timestamp')
                ).values('date').annotate(
                    total=Count('id'),
                    granted=Count('id', filter=Q(consented=True)),
                    revoked=Count('id', filter=Q(consented=False))
                ).order_by('date')
            )
        
        # Current consent status
        consent_status = {
            'medication_adherence': {
                'consented': User.objects.filter(medication_adherence_monitoring_consent=True).count(),
                'total': User.objects.filter(role='patient').count(),
                'percentage': (User.objects.filter(medication_adherence_monitoring_consent=True).count() / 
                              User.objects.filter(role='patient').count() * 100) if User.objects.filter(role='patient').exists() else 0
            },
            'vitals_monitoring': {
                'consented': User.objects.filter(vitals_monitoring_consent=True).count(),
                'total': User.objects.filter(role='patient').count(),
                'percentage': (User.objects.filter(vitals_monitoring_consent=True).count() / 
                              User.objects.filter(role='patient').count() * 100) if User.objects.filter(role='patient').exists() else 0
            },
            'research': {
                'consented': User.objects.filter(research_consent=True).count(),
                'total': User.objects.filter(role='patient').count(),
                'percentage': (User.objects.filter(research_consent=True).count() / 
                              User.objects.filter(role='patient').count() * 100) if User.objects.filter(role='patient').exists() else 0
            }
        }
        
        # Return the widget data
        return {
            'consent_metrics': consent_metrics,
            'activity_by_type': activity_by_type,
            'activity_by_date': activity_by_date,
            'consent_status': consent_status,
            'time_period': time_period,
            'consent_type': consent_type
        }
    
    def _calculate_start_date(self, time_period):
        """Calculate the start date based on the time period string."""
        now = timezone.now()
        
        if time_period == '7d':
            return now - timedelta(days=7)
        elif time_period == '30d':
            return now - timedelta(days=30)
        elif time_period == '90d':
            return now - timedelta(days=90)
        elif time_period == '6m':
            return now - timedelta(days=180)
        elif time_period == '1y':
            return now - timedelta(days=365)
        else:
            # Default to 30 days
            return now - timedelta(days=30)
    
    def _apply_adherence_filters(self, queryset, user, condition=None, medication=None):
        """Apply role-based and parameter filters to adherence records."""
        from users.models import PatientProfile, PatientCondition
        
        # Role-based filtering
        if user.role == 'patient':
            # Patients can only see their own adherence
            if hasattr(user, 'patient_profile'):
                queryset = queryset.filter(patient=user.patient_profile)
            else:
                return queryset.none()
        
        elif user.role == 'caregiver':
            # Caregivers can see patients they are authorized for
            patient_profiles = PatientProfile.objects.filter(authorized_caregivers=user)
            queryset = queryset.filter(patient__in=patient_profiles)
        
        elif user.role == 'pharmco':
            # Pharma companies can see adherence for patients who have consented
            queryset = queryset.filter(patient__medication_adherence_opt_in=True)
        
        elif user.role == 'researcher':
            # Researchers can see anonymized data for research-consented patients
            if hasattr(user, 'researcher_profile') and user.researcher_profile.is_verified:
                queryset = queryset.filter(patient__user__research_consent=True)
            else:
                return queryset.none()
        
        # Apply condition filter
        if condition:
            patient_conditions = PatientCondition.objects.filter(
                condition_name__icontains=condition
            )
            patient_ids = patient_conditions.values_list('patient_id', flat=True)
            queryset = queryset.filter(patient_id__in=patient_ids)
        
        # Apply medication filter
        if medication:
            queryset = queryset.filter(
                prescription__medication__name__icontains=medication
            )
        
        return queryset
    
    def _apply_vitals_filters(self, queryset, user, metric=None, patient_id=None):
        """Apply role-based and parameter filters to vitals records."""
        from users.models import PatientProfile
        
        # Role-based filtering
        if user.role == 'patient':
            # Patients can only see their own vitals
            if hasattr(user, 'patient_profile'):
                queryset = queryset.filter(patient=user.patient_profile)
            else:
                return queryset.none()
        
        elif user.role == 'caregiver':
            # Caregivers can see patients they are authorized for
            patient_profiles = PatientProfile.objects.filter(authorized_caregivers=user)
            queryset = queryset.filter(patient__in=patient_profiles)
        
        elif user.role == 'pharmco':
            # Pharma companies can see vitals for patients who have consented
            queryset = queryset.filter(patient__vitals_monitoring_opt_in=True)
        
        elif user.role == 'researcher':
            # Researchers can see anonymized data for research-consented patients
            if hasattr(user, 'researcher_profile') and user.researcher_profile.is_verified:
                queryset = queryset.filter(patient__user__research_consent=True)
            else:
                return queryset.none()
        
        # Apply metric filter
        if metric:
            queryset = queryset.filter(metric_type=metric)
        
        # Apply patient filter
        if patient_id and (user.role in ['admin', 'provider', 'compliance'] or user.is_staff):
            queryset = queryset.filter(patient_id=patient_id)
        
        return queryset
    
    def _calculate_adherence_metric(self, metric, parameters, user):
        """Calculate a specific adherence metric."""
        # Get parameters
        time_period = parameters.get('time_period', '30d')
        condition = parameters.get('condition')
        medication = parameters.get('medication')
        
        # Get adherence data
        adherence_data = self.get_adherence_metrics(time_period, condition, medication, user)
        
        # Calculate the metric based on the calculation method
        method = metric.calculation_method
        
        if method == 'overall_adherence_rate':
            return {
                'metric_name': metric.name,
                'value': adherence_data['overall_metrics']['avg_adherence_rate'],
                'units': metric.units or '%'
            }
        
        elif method == 'medication_comparison':
            # Return adherence rates by medication for comparison
            return {
                'metric_name': metric.name,
                'values': adherence_data['adherence_by_medication'],
                'units': metric.units or '%'
            }
        
        elif method == 'trend_analysis':
            # Return adherence trend over time
            return {
                'metric_name': metric.name,
                'values': adherence_data['adherence_by_date'],
                'units': metric.units or '%'
            }
        
        else:
            raise ValueError(f"Unsupported adherence calculation method: {method}")
    
    def _calculate_vitals_metric(self, metric, parameters, user):
        """Calculate a specific vitals metric."""
        # Get parameters
        time_period = parameters.get('time_period', '30d')
        metric_type = parameters.get('metric_type')
        patient_id = parameters.get('patient_id')
        
        # Get vitals data
        vitals_data = self.get_vitals_trends(time_period, metric_type, patient_id, user)
        
        # Calculate the metric based on the calculation method
        method = metric.calculation_method
        
        if method == 'average_value':
            # Return average value for the specified vital metric
            if 'overall_metrics' in vitals_data and 'avg_value' in vitals_data['overall_metrics']:
                return {
                    'metric_name': metric.name,
                    'value': vitals_data['overall_metrics']['avg_value'],
                    'units': metric.units or ''
                }
            else:
                # If no specific metric was selected, return metrics summary
                return {
                    'metric_name': metric.name,
                    'values': vitals_data['metrics_summary'],
                    'units': metric.units or ''
                }
        
        elif method == 'trend_analysis':
            # Return vitals trend over time
            return {
                'metric_name': metric.name,
                'values': vitals_data['vitals_by_date'],
                'units': metric.units or ''
            }
        
        else:
            raise ValueError(f"Unsupported vitals calculation method: {method}")
    
    def _calculate_provider_metric(self, metric, parameters, user):
        """Calculate a specific provider performance metric."""
        # Get parameters
        time_period = parameters.get('time_period', '30d')
        provider_id = parameters.get('provider_id')
        
        # Get provider performance data
        performance_data = self.get_provider_performance(provider_id, None, time_period, user)
        
        # Calculate the metric based on the calculation method
        method = metric.calculation_method
        
        if method == 'consultation_efficiency':
            # Return average consultation duration
            return {
                'metric_name': metric.name,
                'value': performance_data['overall_metrics']['avg_duration'],
                'units': metric.units or 'minutes'
            }
        
        elif method == 'patient_satisfaction':
            # Return average patient satisfaction rating
            # This would require additional data not shown in the example
            return {
                'metric_name': metric.name,
                'value': performance_data['overall_metrics'].get('avg_rating', 'N/A'),
                'units': metric.units or 'rating'
            }
        
        elif method == 'completion_rate':
            # Return appointment completion rate
            return {
                'metric_name': metric.name,
                'value': performance_data['overall_metrics']['completion_rate'],
                'units': metric.units or '%'
            }
        
        else:
            raise ValueError(f"Unsupported provider calculation method: {method}")
    
    def _calculate_population_metric(self, metric, parameters, user):
        """Calculate a specific population health metric."""
        # Get parameters
        condition = parameters.get('condition')
        demographic = parameters.get('demographic')
        
        # Get population health data
        population_data = self.get_population_health(condition, demographic, None, user)
        
        # Calculate the metric based on the calculation method
        method = metric.calculation_method
        
        if method == 'condition_prevalence':
            # Return condition prevalence
            if 'condition_distribution' in population_data:
                # If no specific condition, return distribution
                return {
                    'metric_name': metric.name,
                    'values': population_data['condition_distribution'],
                    'units': metric.units or '%'
                }
            else:
                # If specific condition, return count
                return {
                    'metric_name': metric.name,
                    'value': population_data['overall_metrics']['total_patients'],
                    'units': metric.units or 'patients'
                }
        
        elif method == 'demographic_distribution':
            # Return demographic distribution
            if demographic == 'age':
                return {
                    'metric_name': metric.name,
                    'values': population_data['age_distribution'],
                    'units': metric.units or '%'
                }
            elif demographic == 'gender':
                return {
                    'metric_name': metric.name,
                    'values': population_data['gender_distribution'],
                    'units': metric.units or '%'
                }
            else:
                # Default to age distribution
                return {
                    'metric_name': metric.name,
                    'values': population_data['age_distribution'],
                    'units': metric.units or '%'
                }
        
        else:
            raise ValueError(f"Unsupported population calculation method: {method}")
    
    def _calculate_medication_metric(self, metric, parameters, user):
        """Calculate a specific medication efficacy metric."""
        # Implementation would depend on the specific metrics needed
        # For demo purposes, return a placeholder
        return {
            'metric_name': metric.name,
            'value': 85.2,  # Placeholder value
            'units': metric.units or '%'
        }
    
    def _calculate_telemedicine_metric(self, metric, parameters, user):
        """Calculate a specific telemedicine usage metric."""
        # Implementation would depend on the specific metrics needed
        # For demo purposes, return a placeholder
        return {
            'metric_name': metric.name,
            'value': 42.7,  # Placeholder value
            'units': metric.units or 'minutes'
        }
