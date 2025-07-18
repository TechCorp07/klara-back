import logging
from datetime import datetime, timedelta
from django.utils import timezone
from django.db.models import Count, Avg, Sum, F, Q, ExpressionWrapper, FloatField, DateTimeField, Min, Max
from django.db.models.functions import TruncDay, TruncWeek, TruncMonth, Cast
from django.contrib.auth import get_user_model

User = get_user_model()
logger = logging.getLogger('hipaa_audit')

class ReportGeneratorService:
    """Service for generating reports based on configurations."""
    
    def generate_report(self, configuration, user):
        """
        Generate a report based on the configuration.
        
        Args:
            configuration: ReportConfiguration instance
            user: User requesting the report
            
        Returns:
            dict: Report results as JSON
        """
        # Log the beginning of report generation
        logger.info(
            f"REPORT_GENERATION_STARTED: User {user.username} (ID: {user.id}) "
            f"started generating report from configuration {configuration.id} ({configuration.name})"
        )
        
        # Choose generator method based on report type
        if configuration.report_type == 'patient_adherence':
            return self._generate_adherence_report(configuration, user)
        elif configuration.report_type == 'patient_vitals':
            return self._generate_vitals_report(configuration, user)
        elif configuration.report_type == 'provider_performance':
            return self._generate_provider_performance_report(configuration, user)
        elif configuration.report_type == 'population_health':
            return self._generate_population_health_report(configuration, user)
        elif configuration.report_type == 'medication_efficacy':
            return self._generate_medication_efficacy_report(configuration, user)
        elif configuration.report_type == 'phi_access':
            return self._generate_phi_access_report(configuration, user)
        elif configuration.report_type == 'consent_activity':
            return self._generate_consent_activity_report(configuration, user)
        elif configuration.report_type == 'telemedicine_usage':
            return self._generate_telemedicine_usage_report(configuration, user)
        elif configuration.report_type == 'custom':
            return self._generate_custom_report(configuration, user)
        else:
            raise ValueError(f"Unsupported report type: {configuration.report_type}")
    
    def _generate_adherence_report(self, configuration, user):
        """Generate a medication adherence report."""
        # Get parameters from configuration
        params = configuration.parameters
        time_period = params.get('time_period', '30d')
        include_demographics = params.get('include_demographics', False)
        condition_filter = params.get('condition')
        medication_filter = params.get('medication')
        
        # Calculate start date based on time period
        start_date = self._calculate_start_date(time_period)
        
        # Import here to avoid circular imports
        from medication.models import AdherenceRecord, Prescription
        
        # Base query
        adherence_records = AdherenceRecord.objects.filter(
            recorded_date__gte=start_date
        )
        
        # Apply filters based on role and parameters
        adherence_records = self._apply_adherence_filters(
            adherence_records, user, condition_filter, medication_filter
        )
        
        # Calculate adherence metrics
        adherence_metrics = adherence_records.aggregate(
            total_records=Count('id'),
            total_patients=Count('patient', distinct=True),
            total_medications=Count('prescription__medication', distinct=True),
            avg_adherence_rate=Avg('adherence_rate')
        )
        
        # Group adherence by day/week depending on time period
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
            ).order_by('-count')
        )
        
        # Calculate demographic data if requested
        demographic_data = {}
        if include_demographics and (user.role in ['admin', 'provider', 'compliance', 'researcher'] or user.is_staff):
            # Group by age range
            from django.db.models.functions import ExtractYear
            current_year = timezone.now().year
            
            demographic_data['by_age_range'] = list(
                adherence_records.annotate(
                    age=ExpressionWrapper(
                        current_year - ExtractYear('patient__user__date_of_birth'),
                        output_field=FloatField()
                    )
                ).values('age').annotate(
                    count=Count('id'),
                    avg_rate=Avg('adherence_rate')
                ).order_by('age')
            )
            
            # Convert to age ranges
            age_ranges = {'18-30': [], '31-45': [], '46-60': [], '61-75': [], '75+': []}
            for item in demographic_data['by_age_range']:
                age = item['age']
                if age <= 30:
                    age_ranges['18-30'].append(item)
                elif age <= 45:
                    age_ranges['31-45'].append(item)
                elif age <= 60:
                    age_ranges['46-60'].append(item)
                elif age <= 75:
                    age_ranges['61-75'].append(item)
                else:
                    age_ranges['75+'].append(item)
            
            # Calculate average for each age range
            demographic_data['by_age_range'] = []
            for age_range, items in age_ranges.items():
                if items:
                    total_count = sum(item['count'] for item in items)
                    weighted_avg = sum(item['count'] * item['avg_rate'] for item in items) / total_count
                    demographic_data['by_age_range'].append({
                        'age_range': age_range,
                        'count': total_count,
                        'avg_rate': weighted_avg
                    })
            
            # Group by gender
            demographic_data['by_gender'] = list(
                adherence_records.values(
                    gender=F('patient__user__profile__gender')
                ).annotate(
                    count=Count('id'),
                    avg_rate=Avg('adherence_rate')
                ).order_by('gender')
            )
        
        # Construct report results
        results = {
            'report_type': 'patient_adherence',
            'generated_at': timezone.now().isoformat(),
            'time_period': time_period,
            'metrics': adherence_metrics,
            'adherence_by_date': adherence_by_date,
            'adherence_by_medication': adherence_by_medication,
        }
        
        if include_demographics and demographic_data:
            results['demographic_data'] = demographic_data
        
        return results
    
    def _generate_vitals_report(self, configuration, user):
        """Generate a patient vitals report."""
        # Get parameters from configuration
        params = configuration.parameters
        time_period = params.get('time_period', '30d')
        metric = params.get('metric')  # e.g., 'heart_rate', 'blood_pressure', etc.
        patient_id = params.get('patient_id')
        
        # Calculate start date based on time period
        start_date = self._calculate_start_date(time_period)
        
        # Import here to avoid circular imports
        from healthcare.models import Vital
        
        # Base query
        vitals = Vital.objects.filter(
            recorded_at__gte=start_date
        )
        
        # Apply filters based on role and parameters
        vitals = self._apply_vitals_filters(vitals, user, metric, patient_id)
        
        # Calculate vitals metrics
        vitals_metrics = vitals.aggregate(
            total_records=Count('id'),
            total_patients=Count('patient', distinct=True)
        )
        
        # Add metric-specific aggregates if a single metric is selected
        if metric:
            vitals_metrics.update(
                vitals.aggregate(
                    avg_value=Avg('value'),
                    min_value=Min('value'),
                    max_value=Max('value')
                )
            )
        
        # Group vitals by date
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
        if not metric:
            vitals_by_metric = list(
                vitals.values('metric_type').annotate(
                    count=Count('id'),
                    avg_value=Avg('value'),
                    min_value=Min('value'),
                    max_value=Max('value')
                ).order_by('metric_type')
            )
        else:
            vitals_by_metric = []
        
        # Get patient-level statistics if user has permission
        patient_stats = []
        if user.role in ['admin', 'provider', 'compliance'] or user.is_staff:
            patient_stats = list(
                vitals.values(
                    'patient_id',
                    'patient__user__username',
                    'patient__user__first_name',
                    'patient__user__last_name'
                ).annotate(
                    record_count=Count('id'),
                    avg_value=Avg('value')
                ).order_by('-record_count')[:20]  # Limit to top 20 patients
            )
        
        # Construct report results
        results = {
            'report_type': 'patient_vitals',
            'generated_at': timezone.now().isoformat(),
            'time_period': time_period,
            'metric': metric,
            'metrics': vitals_metrics,
            'vitals_by_date': vitals_by_date,
        }
        
        if not metric:
            results['vitals_by_metric'] = vitals_by_metric
        
        if patient_stats:
            results['patient_stats'] = patient_stats
        
        return results
    
    def _generate_provider_performance_report(self, configuration, user):
        """Generate a provider performance report."""
        # Get parameters from configuration
        params = configuration.parameters
        time_period = params.get('time_period', '30d')
        metric = params.get('metric')  # e.g., 'consultation_time', 'patient_count', etc.
        provider_id = params.get('provider_id')
        
        # Calculate start date based on time period
        start_date = self._calculate_start_date(time_period)
        
        # Check access permissions
        if user.role not in ['admin', 'provider', 'compliance'] and not user.is_staff:
            # For providers, only allow their own performance report
            if user.role == 'provider':
                provider_id = user.id
            else:
                raise PermissionError("You don't have permission to access provider performance reports.")
        
        # Import necessary models
        from telemedicine.models import VideoConsultation
        from django.db.models import Avg, Count, Min, Max, DurationField
        
        # Base queries
        consultations = VideoConsultation.objects.filter(
            scheduled_time__gte=start_date,
            status='COMPLETED'
        )
        
        # Apply provider filter if specified
        if provider_id:
            consultations = consultations.filter(provider_id=provider_id)
        
        # Calculate performance metrics
        performance_metrics = consultations.aggregate(
            total_consultations=Count('id'),
            avg_duration=Avg('duration'),
            total_providers=Count('provider', distinct=True),
            total_patients=Count('patient', distinct=True)
        )
        
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
        
        # Group by date
        if time_period in ['7d', '30d']:
            # Daily grouping for shorter periods
            consultations_by_date = list(
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
            consultations_by_date = list(
                consultations.annotate(
                    date=TruncWeek('scheduled_time')
                ).values('date').annotate(
                    count=Count('id'),
                    avg_duration=Avg('duration'),
                    avg_rating=Avg('rating')
                ).order_by('date')
            )
        
        # Specialty performance comparison if user has permission
        specialty_comparison = []
        if user.role in ['admin', 'compliance'] or user.is_staff:
            from users.models import ProviderProfile
            
            specialty_comparison = list(
                consultations.values(
                    'provider__specialty'
                ).annotate(
                    provider_count=Count('provider', distinct=True),
                    consultation_count=Count('id'),
                    avg_duration=Avg('duration'),
                    avg_rating=Avg('rating')
                ).order_by('-consultation_count')
            )
        
        # Construct report results
        results = {
            'report_type': 'provider_performance',
            'generated_at': timezone.now().isoformat(),
            'time_period': time_period,
            'metrics': performance_metrics,
            'provider_metrics': provider_metrics,
            'consultations_by_date': consultations_by_date,
        }
        
        if specialty_comparison:
            results['specialty_comparison'] = specialty_comparison
        
        return results
    
    def _generate_population_health_report(self, configuration, user):
        """Generate a population health report."""
        # Get parameters from configuration
        params = configuration.parameters
        condition = params.get('condition')
        demographic = params.get('demographic')  # e.g., 'age', 'gender', etc.
        metric = params.get('metric')  # e.g., 'adherence_rate', 'hospitalization_rate', etc.
        
        # Check access permissions
        if user.role not in ['admin', 'provider', 'compliance', 'researcher'] and not user.is_staff:
            if user.role == 'researcher' and hasattr(user, 'researcher_profile'):
                if not user.researcher_profile.is_verified:
                    raise PermissionError("Only verified researchers can access population health reports.")
            else:
                raise PermissionError("You don't have permission to access population health reports.")
        
        # Import necessary models
        from users.models import PatientProfile, PatientCondition
        from medication.models import AdherenceRecord
        
        # Base queries
        patients = PatientProfile.objects.all()
        
        # Apply condition filter if specified
        if condition:
            patient_conditions = PatientCondition.objects.filter(
                condition_name__icontains=condition
            )
            patients = patients.filter(id__in=patient_conditions.values('patient_id'))
        
        # Calculate overall metrics
        population_metrics = {
            'total_patients': patients.count(),
        }
        
        # Demographic analysis
        demographic_analysis = {}
        
        # Age distribution
        from django.db.models.functions import ExtractYear
        current_year = timezone.now().year
        
        age_distribution = []
        # This would be joined with the User model in a real implementation
        # For simplicity, we're assuming a direct relationship here
        age_groups = [
            {'name': '18-30', 'min': 18, 'max': 30},
            {'name': '31-45', 'min': 31, 'max': 45},
            {'name': '46-60', 'min': 46, 'max': 60},
            {'name': '61-75', 'min': 61, 'max': 75},
            {'name': '75+', 'min': 76, 'max': 120}
        ]
        
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
                'percentage': (count / population_metrics['total_patients'] * 100) if population_metrics['total_patients'] > 0 else 0
            })
        
        demographic_analysis['age_distribution'] = age_distribution
        
        # Gender distribution
        gender_distribution = list(
            patients.values(
                'user__profile__gender'
            ).annotate(
                count=Count('id')
            ).order_by('user__profile__gender')
        )
        
        for item in gender_distribution:
            item['percentage'] = (item['count'] / population_metrics['total_patients'] * 100) if population_metrics['total_patients'] > 0 else 0
        
        demographic_analysis['gender_distribution'] = gender_distribution
        
        # Condition distribution if no specific condition is specified
        if not condition:
            condition_distribution = list(
                PatientCondition.objects.values(
                    'condition_name'
                ).annotate(
                    count=Count('id')
                ).order_by('-count')[:10]  # Top 10 conditions
            )
            
            for item in condition_distribution:
                item['percentage'] = (item['count'] / population_metrics['total_patients'] * 100) if population_metrics['total_patients'] > 0 else 0
            
            demographic_analysis['condition_distribution'] = condition_distribution
        
        # Medication adherence metrics if available
        adherence_metrics = {}
        try:
            from medication.models import AdherenceRecord
            
            # Overall adherence rate
            adherence_records = AdherenceRecord.objects.filter(
                patient__in=patients
            )
            
            if adherence_records.exists():
                adherence_metrics['overall_adherence_rate'] = adherence_records.aggregate(
                    avg_rate=Avg('adherence_rate')
                )['avg_rate']
                
                # Adherence by age group
                for group in age_groups:
                    min_birth_year = current_year - group['max']
                    max_birth_year = current_year - group['min']
                    
                    group_patients = patients.filter(
                        user__date_of_birth__year__gte=min_birth_year,
                        user__date_of_birth__year__lte=max_birth_year
                    )
                    
                    group_adherence = adherence_records.filter(
                        patient__in=group_patients
                    ).aggregate(
                        avg_rate=Avg('adherence_rate')
                    )['avg_rate'] or 0
                    
                    adherence_metrics.setdefault('adherence_by_age', []).append({
                        'age_group': group['name'],
                        'adherence_rate': group_adherence
                    })
                
                # Adherence by gender
                for gender_item in gender_distribution:
                    gender = gender_item['user__profile__gender']
                    gender_patients = patients.filter(
                        user__profile__gender=gender
                    )
                    
                    gender_adherence = adherence_records.filter(
                        patient__in=gender_patients
                    ).aggregate(
                        avg_rate=Avg('adherence_rate')
                    )['avg_rate'] or 0
                    
                    adherence_metrics.setdefault('adherence_by_gender', []).append({
                        'gender': gender,
                        'adherence_rate': gender_adherence
                    })
        except (ImportError, AttributeError):
            # Module not available or structure different
            pass
        
        # Construct report results
        results = {
            'report_type': 'population_health',
            'generated_at': timezone.now().isoformat(),
            'metrics': population_metrics,
            'demographic_analysis': demographic_analysis,
        }
        
        if adherence_metrics:
            results['adherence_metrics'] = adherence_metrics
        
        return results
    
    def _generate_medication_efficacy_report(self, configuration, user):
        """Generate a medication efficacy report."""
        # Get parameters from configuration
        params = configuration.parameters
        medication_id = params.get('medication_id')
        condition_id = params.get('condition_id')
        time_period = params.get('time_period', '90d')
        
        # Calculate start date based on time period
        start_date = self._calculate_start_date(time_period)
        
        # Check access permissions
        if user.role not in ['admin', 'provider', 'pharmco', 'researcher'] and not user.is_staff:
            if user.role == 'researcher' and hasattr(user, 'researcher_profile'):
                if not user.researcher_profile.is_verified:
                    raise PermissionError("Only verified researchers can access medication efficacy reports.")
            elif user.role != 'pharmco':
                raise PermissionError("You don't have permission to access medication efficacy reports.")
        
        # Import necessary models
        from medication.models import Medication, Prescription, AdherenceRecord, SideEffect
        from users.models import PatientCondition
        from healthcare.models import Vital
        
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
        
        # Vitals changes for patients on this medication (if available)
        vitals_changes = {}
        try:
            # Get patients on this medication
            patient_ids = prescriptions.values_list('patient_id', flat=True).distinct()
            
            # Get relevant vitals measurements
            vitals = Vital.objects.filter(
                patient_id__in=patient_ids,
                recorded_at__gte=start_date
            )
            
            if vitals.exists():
                # Group by patient and metric type to calculate changes
                from django.db.models import Min, Max
                
                # For each patient and vital type, get first and last measurement
                patient_vitals = []
                for patient_id in patient_ids:
                    for metric_type in vitals.filter(patient_id=patient_id).values_list('metric_type', flat=True).distinct():
                        patient_metric_vitals = vitals.filter(
                            patient_id=patient_id,
                            metric_type=metric_type
                        ).order_by('recorded_at')
                        
                        if patient_metric_vitals.count() >= 2:
                            first_value = patient_metric_vitals.first().value
                            last_value = patient_metric_vitals.last().value
                            change = last_value - first_value
                            percent_change = (change / first_value * 100) if first_value != 0 else 0
                            
                            patient_vitals.append({
                                'patient_id': patient_id,
                                'metric_type': metric_type,
                                'first_value': first_value,
                                'last_value': last_value,
                                'change': change,
                                'percent_change': percent_change
                            })
                
                # Calculate average changes by metric type
                if patient_vitals:
                    metric_types = set(item['metric_type'] for item in patient_vitals)
                    
                    for metric_type in metric_types:
                        metric_items = [item for item in patient_vitals if item['metric_type'] == metric_type]
                        avg_change = sum(item['change'] for item in metric_items) / len(metric_items)
                        avg_percent_change = sum(item['percent_change'] for item in metric_items) / len(metric_items)
                        
                        vitals_changes[metric_type] = {
                            'avg_change': avg_change,
                            'avg_percent_change': avg_percent_change,
                            'patients_count': len(metric_items)
                        }
        except (ImportError, AttributeError):
            # Module not available or structure different
            pass
        
        # Construct report results
        results = {
            'report_type': 'medication_efficacy',
            'generated_at': timezone.now().isoformat(),
            'time_period': time_period,
            'metrics': efficacy_metrics,
        }
        
        if medication_id:
            results['medication'] = {
                'id': medication.id,
                'name': medication.name,
                'manufacturer': medication.manufacturer
            }
        
        if condition_id:
            results['condition'] = {
                'id': condition.id,
                'name': condition.condition_name
            }
        
        if vitals_changes:
            results['vitals_changes'] = vitals_changes
        
        return results
    
    def _generate_phi_access_report(self, configuration, user):
        """Generate a PHI access audit report."""
        # Check access permissions - only admins and compliance officers
        if user.role not in ['admin', 'compliance'] and not user.is_staff:
            raise PermissionError("Only administrators and compliance officers can access PHI audit reports.")
        
        # Get parameters from configuration
        params = configuration.parameters
        time_period = params.get('time_period', '30d')
        user_id = params.get('user_id')
        access_type = params.get('access_type')
        
        # Calculate start date based on time period
        start_date = self._calculate_start_date(time_period)
        
        # Import necessary models
        from audit.models import PHIAccessLog, SecurityAuditLog
        
        # Base queries
        phi_access_logs = PHIAccessLog.objects.filter(
            access_time__gte=start_date
        )
        
        # Apply filters
        if user_id:
            phi_access_logs = phi_access_logs.filter(user_id=user_id)
        
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
        
        # Top users accessing PHI
        top_users = list(
            phi_access_logs.values(
                'user_id',
                'user__username',
                'user__role'
            ).annotate(
                access_count=Count('id')
            ).order_by('-access_count')[:20]  # Top 20 users
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
        
        # Security incidents (if available)
        security_incidents = []
        try:
            security_logs = SecurityAuditLog.objects.filter(
                timestamp__gte=start_date,
                event_type__in=['AUTH_FAILURE', '2FA_FAILURE', 'UNAUTHORIZED_ACCESS']
            )
            
            if security_logs.exists():
                security_incidents = list(
                    security_logs.values(
                        'id', 'user_id', 'user__username', 'event_type',
                        'description', 'ip_address', 'timestamp'
                    ).order_by('-timestamp')
                )
        except (ImportError, AttributeError):
            # Module not available or structure different
            pass
        
        # Construct report results
        results = {
            'report_type': 'phi_access',
            'generated_at': timezone.now().isoformat(),
            'time_period': time_period,
            'metrics': access_metrics,
            'access_by_role': access_by_role,
            'access_by_type': access_by_type,
            'top_users': top_users,
            'access_by_date': access_by_date,
        }
        
        if security_incidents:
            results['security_incidents'] = security_incidents
        
        return results
    
    def _generate_consent_activity_report(self, configuration, user):
        """Generate a consent activity report."""
        # Check access permissions - only admins and compliance officers
        if user.role not in ['admin', 'compliance'] and not user.is_staff:
            raise PermissionError("Only administrators and compliance officers can access consent activity reports.")
        
        # Get parameters from configuration
        params = configuration.parameters
        time_period = params.get('time_period', '30d')
        consent_type = params.get('consent_type')
        
        # Calculate start date based on time period
        start_date = self._calculate_start_date(time_period)
        
        # Import necessary models
        from users.models import ConsentRecord
        
        # Base queries
        consent_logs = ConsentRecord.objects.filter(
            signature_timestamp=start_date
        )
        
        # Apply filters
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
        
        # Activity by user role
        activity_by_role = list(
            consent_logs.values(
                'user__role'
            ).annotate(
                total=Count('id'),
                granted=Count('id', filter=Q(consented=True)),
                revoked=Count('id', filter=Q(consented=False)),
                unique_users=Count('user', distinct=True)
            ).order_by('user__role')
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
        
        # Current consent status summary
        from users.models import User
        
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
            },
            'data_sharing': {
                'consented': User.objects.filter(data_sharing_consent=True).count(),
                'total': User.objects.filter(role='patient').count(),
                'percentage': (User.objects.filter(data_sharing_consent=True).count() / 
                              User.objects.filter(role='patient').count() * 100) if User.objects.filter(role='patient').exists() else 0
            }
        }
        
        # Construct report results
        results = {
            'report_type': 'consent_activity',
            'generated_at': timezone.now().isoformat(),
            'time_period': time_period,
            'metrics': consent_metrics,
            'activity_by_type': activity_by_type,
            'activity_by_role': activity_by_role,
            'activity_by_date': activity_by_date,
            'current_consent_status': consent_status
        }
        
        return results
    
    def _generate_telemedicine_usage_report(self, configuration, user):
        """Generate a telemedicine usage report."""
        # Get parameters from configuration
        params = configuration.parameters
        time_period = params.get('time_period', '30d')
        provider_id = params.get('provider_id')
        
        # Calculate start date based on time period
        start_date = self._calculate_start_date(time_period)
        
        # Check access permissions
        if user.role not in ['admin', 'provider', 'compliance'] and not user.is_staff:
            if user.role == 'provider':
                provider_id = user.id
            elif user.role != 'pharmco':
                raise PermissionError("You don't have permission to access telemedicine usage reports.")
        
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
        
        # Top providers by consultation count
        top_providers = []
        if not provider_id and (user.role in ['admin', 'compliance'] or user.is_staff):
            top_providers = list(
                consultations.values(
                    'provider_id',
                    'provider__user__username',
                    'provider__user__first_name',
                    'provider__user__last_name',
                    'provider__specialty'
                ).annotate(
                    consultation_count=Count('id'),
                    completed_count=Count('id', filter=Q(status='COMPLETED')),
                    avg_duration=Avg('duration', filter=Q(status='COMPLETED')),
                    patient_count=Count('patient', distinct=True)
                ).order_by('-consultation_count')[:10]  # Top 10 providers
            )
        
        # Patient satisfaction metrics if available
        satisfaction_metrics = {}
        if consultations.filter(rating__isnull=False).exists():
            satisfaction_metrics = consultations.filter(
                rating__isnull=False
            ).aggregate(
                avg_rating=Avg('rating'),
                rating_count=Count('rating')
            )
            
            # Ratings distribution
            ratings_distribution = list(
                consultations.filter(
                    rating__isnull=False
                ).values(
                    'rating'
                ).annotate(
                    count=Count('id')
                ).order_by('rating')
            )
            
            satisfaction_metrics['ratings_distribution'] = ratings_distribution
        
        # Construct report results
        results = {
            'report_type': 'telemedicine_usage',
            'generated_at': timezone.now().isoformat(),
            'time_period': time_period,
            'metrics': usage_metrics,
            'usage_by_status': usage_by_status,
            'usage_by_date': usage_by_date,
        }
        
        if top_providers:
            results['top_providers'] = top_providers
        
        if satisfaction_metrics:
            results['satisfaction_metrics'] = satisfaction_metrics
        
        return results
    
    def _generate_custom_report(self, configuration, user):
        """Generate a custom report based on configuration parameters."""
        # Get parameters from configuration
        params = configuration.parameters
        report_name = params.get('report_name', 'Custom Report')
        data_sources = params.get('data_sources', [])
        filters = params.get('filters', {})
        metrics = params.get('metrics', [])
        groupings = params.get('groupings', [])
        
        # Check access permissions - custom reports should be restricted
        if not configuration.created_by == user and not user.is_staff and user.role != 'admin':
            if user.role not in configuration.allowed_roles:
                raise PermissionError("You don't have permission to generate this custom report.")
        
        # Custom reports require more complex logic to build dynamically
        # This would typically involve a query builder or similar approach
        
        # For the purposes of this example, we'll return a placeholder
        results = {
            'report_type': 'custom',
            'report_name': report_name,
            'generated_at': timezone.now().isoformat(),
            'note': 'Custom report generation is implemented specifically for each custom report configuration.',
            'parameters': params
        }
        
        # Log that this is a placeholder
        logger.warning(
            f"CUSTOM_REPORT_PLACEHOLDER: User {user.username} (ID: {user.id}) "
            f"attempted to generate custom report '{report_name}', but implementation is placeholder."
        )
        
        return results
    
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

    def _generate_pharmaceutical_trial_report(self, configuration, user):
        """Generate pharmaceutical trial data report."""
        # Check access permissions - only pharma companies and authorized researchers
        if user.role not in ['pharmco', 'researcher', 'admin', 'compliance'] and not user.is_staff:
            if user.role == 'researcher' and hasattr(user, 'researcher_profile'):
                if not user.researcher_profile.is_verified:
                    raise PermissionError("Only verified researchers can access trial reports.")
            else:
                raise PermissionError("You don't have permission to access pharmaceutical trial reports.")
        
        params = configuration.parameters
        medication_id = params.get('medication_id')
        trial_phase = params.get('trial_phase')
        time_period = params.get('time_period', '90d')
        
        # Calculate start date
        start_date = self._calculate_start_date(time_period)
        
        from medication.models import Medication, AdherenceRecord, SideEffect
        from healthcare.models import VitalSign
        
        # Get trial medications
        medications = Medication.objects.filter(
            for_rare_condition=True,
            created_at__gte=start_date
        )
        
        if medication_id:
            medications = medications.filter(id=medication_id)
        
        if trial_phase:
            medications = medications.filter(
                trial_phase=trial_phase  # Assuming this field exists
            )
        
        trial_results = {
            'report_type': 'pharmaceutical_trial',
            'generated_at': timezone.now().isoformat(),
            'time_period': time_period,
            'trial_phase': trial_phase,
            'medications_analyzed': medications.count(),
            'patient_enrollment': {},
            'adherence_data': {},
            'efficacy_metrics': {},
            'safety_data': {},
            'demographic_breakdown': {}
        }
        
        for medication in medications:
            med_data = {
                'medication_name': medication.name,
                'patients_enrolled': medication.patients.count(),
                'adherence_rate': self._calculate_medication_adherence_rate(medication),
                'side_effects': self._get_medication_side_effects(medication),
                'efficacy_indicators': self._get_efficacy_indicators(medication)
            }
            
            trial_results['medications_analyzed'][medication.id] = med_data
        
        return trial_results

    def _generate_real_world_evidence_report(self, configuration, user):
        """Generate real-world evidence report for rare diseases."""
        # Access control for sensitive RWE data
        if user.role not in ['pharmco', 'researcher', 'admin', 'compliance'] and not user.is_staff:
            raise PermissionError("Access denied to real-world evidence reports.")
        
        params = configuration.parameters
        condition = params.get('condition')
        medication = params.get('medication')
        time_period = params.get('time_period', '365d')
        
        start_date = self._calculate_start_date(time_period)
        
        from healthcare.models import MedicalRecord, Condition as ConditionModel
        from medication.models import Medication, AdherenceRecord
        from wearables.models import WearableData
        
        # Get patients with specified rare condition
        condition_records = ConditionModel.objects.filter(
            is_rare_disease=True,
            diagnosis_date__gte=start_date
        )
        
        if condition:
            condition_records = condition_records.filter(name__icontains=condition)
        
        rwe_data = {
            'report_type': 'real_world_evidence',
            'generated_at': timezone.now().isoformat(),
            'time_period': time_period,
            'patient_population': condition_records.count(),
            'treatment_patterns': self._analyze_treatment_patterns(condition_records),
            'outcome_measures': self._analyze_outcomes(condition_records),
            'healthcare_utilization': self._analyze_healthcare_utilization(condition_records),
            'quality_of_life': self._analyze_qol_metrics(condition_records),
            'economic_impact': self._analyze_economic_impact(condition_records)
        }
        
        return rwe_data
