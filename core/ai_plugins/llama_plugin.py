# Copyright 2025: NemesisCyberForce
# App: CryptGuardian 
# File: core/ai_plugins/llama_plugin.py
# Version: 0.1
# Comment: Llama Plugin over Replicate
import replicate
from .base import AIPlugin

class LlamaPlugin(AIPlugin):
    def __init__(self, api_key: str):
        # Setze den API-Schlüssel für Replicate
        self.api_token = api_key
    
    def analyze(self, prompt: str) -> str:
        #  Llama 3 Modell über Replicate API
        output = replicate.run(
            "meta/llama-3-70b-instruct:dd2c4401272e0114efb08b7b8190fe29679e00579ecd003728ce6cefb9097dc7",
            input={
                "prompt": f"<|begin_of_text|><|user|>\n{prompt}<|end_of_text|>\n<|begin_of_text|><|assistant|>\n",
                "temperature": 0.7,
                "max_new_tokens": 1024,
                "top_p": 0.9
            },
            api_token=self.api_token
        )
        
        # Replicate gibt ein Iterator-Objekt zurück
        result = ""
        for item in output:
            result += item
            
        return result
    
    def name(self) -> str:
        return "llama"
