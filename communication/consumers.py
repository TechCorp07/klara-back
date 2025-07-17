import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.auth import get_user_model
from .models import Conversation, Message

User = get_user_model()

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.conversation_id = self.scope['url_route']['kwargs']['conversation_id']
        self.conversation_group_name = f'chat_{self.conversation_id}'
        
        # Check if user is participant in conversation
        if await self.is_participant():
            await self.channel_layer.group_add(
                self.conversation_group_name,
                self.channel_name
            )
            await self.accept()
        else:
            await self.close()
    
    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            self.conversation_group_name,
            self.channel_name
        )
    
    async def receive(self, text_data):
        data = json.loads(text_data)
        message_content = data['message']
        
        # Save message to database
        message = await self.save_message(message_content)
        
        # Send message to conversation group
        await self.channel_layer.group_send(
            self.conversation_group_name,
            {
                'type': 'chat_message',
                'message': {
                    'id': message.id,
                    'content': message.content,
                    'sender': {
                        'id': message.sender.id,
                        'username': message.sender.username,
                        'full_name': message.sender.get_full_name()
                    },
                    'created_at': message.created_at.isoformat()
                }
            }
        )
    
    async def chat_message(self, event):
        await self.send(text_data=json.dumps(event['message']))
    
    @database_sync_to_async
    def is_participant(self):
        user = self.scope["user"]
        return Conversation.objects.filter(
            id=self.conversation_id,
            participants=user
        ).exists()
    
    @database_sync_to_async
    def save_message(self, content):
        from .services.message_service import send_message
        conversation = Conversation.objects.get(id=self.conversation_id)
        return send_message(conversation, self.scope["user"], content)
