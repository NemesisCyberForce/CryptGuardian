# core/ai_plugins/base.py

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
