import logging
from django.utils import timezone

logger = logging.getLogger(__name__)

# Apple Health does not provide a direct API - data must be accessed through the iOS app
# This service provides methods for handling data sent from the iOS app to our backend

def process_incoming_data(user, data_payload):
    """Process data received from the iOS app."""
    logger.info(f"Processing Apple Health data for user {user.username}")
    
    try:
        # Validate the data payload
        if not isinstance(data_payload, dict) or 'data_type' not in data_payload:
            logger.error("Invalid Apple Health data payload format")
            return {
                'success': False,
                'message': 'Invalid data format',
                'records_processed': 0
            }
        
        # Process based on data type
        data_type = data_payload.get('data_type')
        records = data_payload.get('records', [])
        
        if not records:
            logger.warning(f"Empty records list for {data_type}")
            return {
                'success': True,
                'message': 'No records to process',
                'records_processed': 0
            }
        
        # Import models here to avoid circular imports
        from ..models import WearableIntegration, WearableMeasurement
        
        # Get or create integration
        integration, created = WearableIntegration.objects.get_or_create(
            user=user,
            integration_type='apple_health',
            defaults={
                'status': WearableIntegration.ConnectionStatus.CONNECTED,
                'consent_granted': True,
                'consent_date': timezone.now()
            }
        )
        
        # Update last sync time
        integration.last_sync = timezone.now()
        integration.save(update_fields=['last_sync'])
        
        # Process records based on type
        processed_count = 0
        
        for record in records:
            # Validate record format
            if not isinstance(record, dict) or 'value' not in record or 'date' not in record:
                logger.warning(f"Skipping invalid record format: {record}")
                continue
            
            # Convert date string to datetime
            try:
                date = timezone.datetime.fromisoformat(record['date'])
            except (ValueError, TypeError):
                logger.warning(f"Invalid date format in record: {record['date']}")
                continue
            
            # Generate a unique ID for the record
            external_id = f"apple_health_{data_type}_{date.strftime('%Y%m%d%H%M%S')}_{processed_count}"
            
            # Map Apple Health data type to our measurement type
            measurement_type_map = {
                'steps': WearableMeasurement.MeasurementType.STEPS,
                'heart_rate': WearableMeasurement.MeasurementType.HEART_RATE,
                'weight': WearableMeasurement.MeasurementType.WEIGHT,
                'sleep': WearableMeasurement.MeasurementType.SLEEP,
                'active_energy': WearableMeasurement.MeasurementType.CALORIES,
                'blood_pressure': WearableMeasurement.MeasurementType.BLOOD_PRESSURE,
                'oxygen_saturation': WearableMeasurement.MeasurementType.OXYGEN_SATURATION,
                'blood_glucose': WearableMeasurement.MeasurementType.BLOOD_GLUCOSE,
                'respiratory_rate': WearableMeasurement.MeasurementType.RESPIRATORY_RATE,
                'body_temperature': WearableMeasurement.MeasurementType.TEMPERATURE,
                'body_fat': WearableMeasurement.MeasurementType.BODY_FAT,
                'activity': WearableMeasurement.MeasurementType.ACTIVITY,
                'distance': WearableMeasurement.MeasurementType.DISTANCE,
            }
            
            measurement_type = measurement_type_map.get(data_type)
            if not measurement_type:
                logger.warning(f"Unsupported data type: {data_type}")
                continue
            
            # Handle special case for blood pressure
            if data_type == 'blood_pressure':
                systolic = record.get('systolic')
                diastolic = record.get('diastolic')
                if not systolic or not diastolic:
                    logger.warning(f"Blood pressure record missing systolic or diastolic: {record}")
                    continue
                
                # Create measurement
                measurement, created = WearableMeasurement.objects.update_or_create(
                    user=user,
                    integration_type='apple_health',
                    external_measurement_id=external_id,
                    defaults={
                        'measurement_type': measurement_type,
                        'value': float(systolic),  # Use systolic as primary value
                        'unit': 'mmHg',
                        'measured_at': date,
                        'device_id': record.get('device_id', 'apple_health'),
                        'device_model': record.get('device_model', 'iOS Device'),
                        'systolic': float(systolic),
                        'diastolic': float(diastolic),
                        'additional_data': {
                            'systolic': systolic,
                            'diastolic': diastolic,
                            'source': record.get('source', 'Apple Health')
                        }
                    }
                )
            else:
                # Standard measurement
                measurement, created = WearableMeasurement.objects.update_or_create(
                    user=user,
                    integration_type='apple_health',
                    external_measurement_id=external_id,
                    defaults={
                        'measurement_type': measurement_type,
                        'value': float(record['value']),
                        'unit': record.get('unit', ''),
                        'measured_at': date,
                        'device_id': record.get('device_id', 'apple_health'),
                        'device_model': record.get('device_model', 'iOS Device'),
                        'additional_data': {
                            'source': record.get('source', 'Apple Health'),
                            'metadata': record.get('metadata', {})
                        }
                    }
                )
            
            if created:
                processed_count += 1
                
                # Sync to healthcare app
                from healthcare.models import VitalSign
                
                # Map to VitalSign measurement type
                vitals_type_map = {
                    WearableMeasurement.MeasurementType.STEPS: 'steps',
                    WearableMeasurement.MeasurementType.HEART_RATE: 'heart_rate',
                    WearableMeasurement.MeasurementType.WEIGHT: 'weight',
                    WearableMeasurement.MeasurementType.SLEEP: 'sleep',
                    WearableMeasurement.MeasurementType.BLOOD_PRESSURE: 'blood_pressure',
                    WearableMeasurement.MeasurementType.OXYGEN_SATURATION: 'oxygen_saturation',
                    WearableMeasurement.MeasurementType.BLOOD_GLUCOSE: 'blood_glucose',
                    WearableMeasurement.MeasurementType.RESPIRATORY_RATE: 'respiratory_rate',
                    WearableMeasurement.MeasurementType.TEMPERATURE: 'temperature',
                }
                
                vital_type = vitals_type_map.get(measurement_type)
                if vital_type:
                    if vital_type == 'blood_pressure':
                        vital_sign, created = VitalSign.objects.update_or_create(
                            source='apple_health',
                            source_device_id=record.get('device_id', 'apple_health'),
                            measured_at=date,
                            defaults={
                                'measurement_type': vital_type,
                                'value': f"{systolic}/{diastolic}",
                                'unit': 'mmHg',
                                'blood_pressure': f"{systolic}/{diastolic}",
                                'created_by': user
                            }
                        )
                    else:
                        vital_sign, created = VitalSign.objects.update_or_create(
                            source='apple_health',
                            source_device_id=record.get('device_id', 'apple_health'),
                            measured_at=date,
                            defaults={
                                'measurement_type': vital_type,
                                'value': str(record['value']),
                                'unit': record.get('unit', ''),
                                'created_by': user
                            }
                        )
                    
                    # Update the measurement to mark as synced
                    measurement.synced_to_healthcare = True
                    measurement.healthcare_record_id = vital_sign.id
                    measurement.save(update_fields=['synced_to_healthcare', 'healthcare_record_id'])
        
        return {
            'success': True,
            'message': f'Successfully processed {processed_count} records',
            'records_processed': processed_count
        }
        
    except Exception as e:
        logger.error(f"Error processing Apple Health data: {str(e)}")
        return {
            'success': False,
            'message': f'Error processing data: {str(e)}',
            'records_processed': 0
        }

def generate_mobile_config():
    """Generate configuration for the mobile app."""
    return {
        'required_permissions': [
            'HealthKit',
            'Background App Refresh'
        ],
        'supported_data_types': [
            'steps',
            'heart_rate',
            'weight',
            'sleep',
            'active_energy',
            'blood_pressure',
            'oxygen_saturation',
            'blood_glucose',
            'respiratory_rate',
            'body_temperature',
            'body_fat',
            'activity',
            'distance'
        ]
    }
