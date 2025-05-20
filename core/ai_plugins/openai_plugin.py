# core/ai_plugins/openai_plugin.py

from openai import OpenAI
from .base import AIPlugin

class OpenAIPlugin(AIPlugin):
    def __init__(self, api_key: str):
        self.client = OpenAI(api_key=api_key)

    def analyze(self, prompt: str) -> str:
        response = self.client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}],
        )
        return response.choices[0].message.content.strip()

    def name(self) -> str:
        return "openai"
