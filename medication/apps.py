from django.apps import AppConfig
from django.db.models.signals import post_migrate


class MedicationConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'medication'
    verbose_name = 'Medication Management'

    def ready(self):
        """
        Initialize app when Django starts.
        
        Sets up signal handlers, schedules recurring tasks,
        and performs other initialization.
        """
        # Import signals module to register handlers
        import medication.signals
        
        # Register periodic tasks with Celery Beat if available
        try:
            from django_celery_beat.models import PeriodicTask, IntervalSchedule
            from django.conf import settings
            import logging
            
            logger = logging.getLogger(__name__)
            
            # Register recurring tasks if Celery is enabled
            if getattr(settings, 'CELERY_ENABLED', False):
                logger.info("Registering medication recurring tasks with Celery Beat")
                self._register_periodic_tasks()
                
        except ImportError:
            # django_celery_beat not installed, skip task registration
            pass
        except Exception as e:
            # Log any errors but don't prevent app from starting
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Error registering medication tasks: {str(e)}")
    
    def _register_periodic_tasks(self):
        """Register recurring tasks with Celery Beat."""
        from django_celery_beat.models import PeriodicTask, IntervalSchedule
        
        # Define task schedules
        schedules = {
            'medication_reminders': {
                'every': 15,
                'period': IntervalSchedule.MINUTES,
                'task': 'medication.tasks.send_due_reminders',
                'description': 'Send medication reminders to patients'
            },
            'check_missed_doses': {
                'every': 1,
                'period': IntervalSchedule.HOURS,
                'task': 'medication.tasks.check_missed_doses',
                'description': 'Check for missed medication doses'
            },
            'update_adherence': {
                'every': 6,
                'period': IntervalSchedule.HOURS,
                'task': 'medication.tasks.update_adherence_records',
                'description': 'Update medication adherence records'
            },
            'check_interactions': {
                'every': 24,
                'period': IntervalSchedule.HOURS,
                'task': 'medication.tasks.check_all_patient_interactions',
                'description': 'Check medication interactions for all patients'
            },
            'check_expiring_prescriptions': {
                'every': 24,
                'period': IntervalSchedule.HOURS,
                'task': 'medication.tasks.check_expiring_prescriptions',
                'description': 'Check for prescriptions nearing expiration'
            }
        }
        
        # Create or update schedules
        for name, config in schedules.items():
            # Get or create the interval schedule
            schedule, _ = IntervalSchedule.objects.get_or_create(
                every=config['every'],
                period=config['period']
            )
            
            # Create or update the periodic task
            PeriodicTask.objects.update_or_create(
                name=f"Medication - {name}",
                defaults={
                    'task': config['task'],
                    'interval': schedule,
                    'description': config['description'],
                    'enabled': True
                }
            )
