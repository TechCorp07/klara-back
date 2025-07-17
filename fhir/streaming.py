"""
Real-time data streaming capabilities for Klararety platform.
Implements WebSocket-based streaming for NMOSD indicators and wearable data.
"""
import json
import asyncio
import logging
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.auth.models import AnonymousUser
from django.contrib.auth import get_user_model
from fhir.models.patient import FHIRPatient
from fhir.models.observation import FHIRObservation

logger = logging.getLogger('fhir')
User = get_user_model()


class DataStreamConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.user = self.scope["user"]
        
        if isinstance(self.user, AnonymousUser):
            await self.close(code=4001)
            return
        
        self.patient_id = self.scope["url_route"]["kwargs"].get("patient_id")
        if not self.patient_id:
            await self.close(code=4002)
            return
        
        has_access = await self.check_patient_access(self.patient_id, self.user)
        if not has_access:
            await self.close(code=4003)
            return
        
        self.patient_group_name = f"patient_{self.patient_id}"
        
        await self.channel_layer.group_add(
            self.patient_group_name,
            self.channel_name
        )
        
        await self.accept()
        await self.send_initial_data()
        
    async def disconnect(self, close_code):
        if hasattr(self, 'patient_group_name'):
            await self.channel_layer.group_discard(
                self.patient_group_name,
                self.channel_name
            )
    
    async def receive(self, text_data):
        try:
            data = json.loads(text_data)
            message_type = data.get('type')
            
            if message_type == 'subscribe':
                data_type = data.get('data_type')
                if data_type:
                    await self.handle_subscription(data_type)
                    
            elif message_type == 'unsubscribe':
                data_type = data.get('data_type')
                if data_type:
                    await self.handle_unsubscription(data_type)
                    
            elif message_type == 'ping':
                await self.send(text_data=json.dumps({
                    'type': 'pong',
                    'timestamp': data.get('timestamp')
                }))
            else:
                await self.send(text_data=json.dumps({
                    'type': 'error',
                    'message': f"Unknown message type: {message_type}"
                }))
        except json.JSONDecodeError:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': "Invalid JSON"
            }))
        except Exception as e:
            logger.exception(f"Error processing WebSocket message: {e}")
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': str(e)
            }))
    
    async def handle_subscription(self, data_type):
        if not hasattr(self, 'subscriptions'):
            self.subscriptions = set()
        self.subscriptions.add(data_type)
        await self.send(text_data=json.dumps({
            'type': 'subscription_confirmed',
            'data_type': data_type
        }))
    
    async def handle_unsubscription(self, data_type):
        if hasattr(self, 'subscriptions') and data_type in self.subscriptions:
            self.subscriptions.remove(data_type)
        await self.send(text_data=json.dumps({
            'type': 'unsubscription_confirmed',
            'data_type': data_type
        }))
    
    async def send_initial_data(self):
        nmosd_indicators = await self.get_latest_nmosd_indicators(self.patient_id)
        wearable_data = await self.get_latest_wearable_data(self.patient_id)
        
        await self.send(text_data=json.dumps({
            'type': 'initial_data',
            'nmosd_indicators': nmosd_indicators,
            'wearable_data': wearable_data
        }))
    
    async def observation_update(self, event):
        data_type = event.get('data_type')
        if not hasattr(self, 'subscriptions') or data_type not in self.subscriptions:
            return
        await self.send(text_data=json.dumps({
            'type': 'observation_update',
            'data_type': data_type,
            'data': event.get('data')
        }))
    
    async def nmosd_indicator_update(self, event):
        data_type = event.get('data_type')
        if not hasattr(self, 'subscriptions') or data_type not in self.subscriptions:
            return
        await self.send(text_data=json.dumps({
            'type': 'nmosd_indicator_update',
            'data_type': data_type,
            'data': event.get('data')
        }))
    
    async def alert_notification(self, event):
        await self.send(text_data=json.dumps({
            'type': 'alert_notification',
            'alert_type': event.get('alert_type'),
            'severity': event.get('severity'),
            'message': event.get('message'),
            'data': event.get('data')
        }))
    
    @database_sync_to_async
    def check_patient_access(self, patient_id, user):
        try:
            # Possibly the patient is the user
            try:
                patient = FHIRPatient.objects.get(id=patient_id)
                if patient.user and patient.user == user:
                    return True
            except FHIRPatient.DoesNotExist:
                pass
            
            if user.is_staff:
                return True
            return False
        except Exception as e:
            logger.exception(f"Error checking patient access: {e}")
            return False
    
    @database_sync_to_async
    def get_latest_nmosd_indicators(self, patient_id):
        try:
            observations = FHIRObservation.objects.filter(
                patient_id=patient_id,
                is_nmosd_indicator=True
            ).order_by('-effective_date')[:10]
            
            result = []
            for obs in observations:
                result.append({
                    'id': str(obs.id),
                    'type': obs.nmosd_indicator_type,
                    'date': obs.effective_date.isoformat() if obs.effective_date else None,
                    'value': obs.value,
                    'unit': obs.unit,
                    'fhir': obs.to_fhir()
                })
            return result
        except Exception as e:
            logger.exception(f"Error getting latest NMOSD indicators: {e}")
            return []
    
    @database_sync_to_async
    def get_latest_wearable_data(self, patient_id):
        try:
            observations = FHIRObservation.objects.filter(
                patient_id=patient_id,
                wearable_source__isnull=False
            ).exclude(wearable_source='').order_by('-effective_date')[:20]
            
            result = []
            for obs in observations:
                result.append({
                    'id': str(obs.id),
                    'source': obs.wearable_source,
                    'code': obs.code,
                    'display': obs.code_display,
                    'date': obs.effective_date.isoformat() if obs.effective_date else None,
                    'value': obs.value,
                    'unit': obs.unit,
                    'fhir': obs.to_fhir()
                })
            return result
        except Exception as e:
            logger.exception(f"Error getting latest wearable data: {e}")
            return []


def send_observation_update(patient_id, data_type, data):
    from channels.layers import get_channel_layer
    from asgiref.sync import async_to_sync
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        f"patient_{patient_id}",
        {
            'type': 'observation_update',
            'data_type': data_type,
            'data': data
        }
    )

def send_nmosd_indicator_update(patient_id, data_type, data):
    from channels.layers import get_channel_layer
    from asgiref.sync import async_to_sync
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        f"patient_{patient_id}",
        {
            'type': 'nmosd_indicator_update',
            'data_type': data_type,
            'data': data
        }
    )

def send_alert_notification(patient_id, alert_type, severity, message, data=None):
    from channels.layers import get_channel_layer
    from asgiref.sync import async_to_sync
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        f"patient_{patient_id}",
        {
            'type': 'alert_notification',
            'alert_type': alert_type,
            'severity': severity,
            'message': message,
            'data': data or {}
        }
    )
