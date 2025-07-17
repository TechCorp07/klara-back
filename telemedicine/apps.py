from django.apps import AppConfig
from django.db.models.signals import post_migrate


class TelemedicineConfig(AppConfig):
    """Configuration for the Telemedicine app."""
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'telemedicine'
    verbose_name = 'Telemedicine & Virtual Care'
    
    def ready(self):
        """
        Initialize app when Django starts.
        
        Sets up signal handlers, schedules recurring tasks,
        and performs other initialization.
        """
        from django.conf import settings
        import logging
        logger = logging.getLogger(__name__)
        
        # Import signal handlers
        from . import signals
        
        # Register periodic tasks with Celery Beat
        try:
            from django_celery_beat.models import PeriodicTask, IntervalSchedule
            
            # Register recurring tasks if Celery is enabled
            if getattr(settings, 'CELERY_ENABLED', False):
                logger.info("Registering telemedicine recurring tasks with Celery Beat")
                self._register_periodic_tasks()
                
        except ImportError:
            logger.warning("django_celery_beat not installed, skipping task registration")
        except Exception as e:
            logger.error(f"Error registering tasks: {str(e)}")
        
        # Register post-migration hook
        post_migrate.connect(self._create_default_waiting_rooms, sender=self)
    
    def _register_periodic_tasks(self):
        """Register recurring tasks with Celery Beat."""
        from django_celery_beat.models import PeriodicTask, IntervalSchedule
        
        # Define task schedules
        schedules = {
            'appointment_reminders': {
                'every': 1,
                'period': IntervalSchedule.HOURS,
                'task': 'telemedicine.tasks.send_appointment_reminders',
                'description': 'Send reminders for upcoming appointments'
            },
            'missed_appointments': {
                'every': 1,
                'period': IntervalSchedule.HOURS,
                'task': 'telemedicine.tasks.check_missed_appointments',
                'description': 'Mark missed appointments as no-shows'
            },
            'prescription_expiration': {
                'every': 24,
                'period': IntervalSchedule.HOURS,
                'task': 'telemedicine.tasks.check_prescription_expiration',
                'description': 'Mark expired prescriptions'
            },
            'provider_availability': {
                'every': 24,
                'period': IntervalSchedule.HOURS,
                'task': 'telemedicine.tasks.generate_provider_availability',
                'description': 'Generate recurring provider availability'
            },
            'waiting_room_cleanup': {
                'every': 15,
                'period': IntervalSchedule.MINUTES,
                'task': 'telemedicine.tasks.clean_waiting_room',
                'description': 'Clean up waiting room entries'
            },
            'abandoned_consultations': {
                'every': 30,
                'period': IntervalSchedule.MINUTES,
                'task': 'telemedicine.tasks.end_abandoned_consultations',
                'description': 'End consultations that were abandoned'
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
                name=f"Telemedicine - {name}",
                defaults={
                    'task': config['task'],
                    'interval': schedule,
                    'description': config['description'],
                    'enabled': True
                }
            )
    
    def _create_default_waiting_rooms(self, sender, **kwargs):
        """
        Create default waiting rooms for providers after migrations.
        
        This ensures that every provider has at least one waiting room.
        """
        try:
            from django.contrib.auth import get_user_model
            from .models import WaitingRoom
            User = get_user_model()
            
            # Get all providers without waiting rooms
            providers = User.objects.filter(role='provider')
            
            for provider in providers:
                # Check if provider already has a waiting room
                has_waiting_room = WaitingRoom.objects.filter(provider=provider).exists()
                
                if not has_waiting_room:
                    # Create default waiting room
                    WaitingRoom.objects.create(
                        name=f"Dr. {provider.last_name}'s Waiting Room",
                        provider=provider,
                        is_active=True,
                        estimated_wait_time=15,
                        custom_message="Welcome to your virtual appointment. The doctor will see you shortly."
                    )
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Error creating default waiting rooms: {str(e)}")
