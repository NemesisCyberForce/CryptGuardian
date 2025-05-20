# Copyright 2025: NemesisCyberForce
# App: CryptGuardian 
# File: core/ai_plugins/claude_plugin.py
# Version: 0.1
# Comment: Anthropic ClaudeAi Plugin
from anthropic import Anthropic
from .base import AIPlugin

class ClaudePlugin(AIPlugin):
    def __init__(self, api_key: str):
        self.client = Anthropic(api_key=api_key)
    
    def analyze(self, prompt: str) -> str:
        response = self.client.messages.create(
            model="claude-3-7-sonnet-20250219",
            max_tokens=1024,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        return response.content[0].text
    
    def name(self) -> str:
        return "claude"
