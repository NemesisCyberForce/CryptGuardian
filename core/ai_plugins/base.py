# Copyright 2025: NemesisCyberForce
# App: CryptGuardian 
# File: core/ai_plugins/base.py
# Version: 0.1
# Comment: main class AIPlugin

from abc import ABC, abstractmethod

class AIPlugin(ABC):
    @abstractmethod
    def analyze(self, prompt: str) -> str:
        """Hauptfunktion zum Analysieren eines Prompts"""
        pass

    @abstractmethod
    def name(self) -> str:
        """Plugin-Name (z. B. 'openai')"""
        pass
