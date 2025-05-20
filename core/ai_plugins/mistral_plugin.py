
# core/ai_plugins/mistral_plugin.py
from mistralai.client import MistralClient
from mistralai.models.chat_completion import ChatMessage
from .base import AIPlugin

class MistralPlugin(AIPlugin):
    def __init__(self, api_key: str):
        self.client = MistralClient(api_key=api_key)
    
    def analyze(self, prompt: str) -> str:
        messages = [ChatMessage(role="user", content=prompt)]
        response = self.client.chat(
            model="mistral-medium",  # oder andere verfügbare Modelle wie "mistral-large"
            messages=messages
        )
        return response.choices[0].message.content
    
    def name(self) -> str:
        return "mistral"
