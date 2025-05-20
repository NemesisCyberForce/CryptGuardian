# Copyright 2025: NemesisCyberForce
# App: CryptGuardian 
# File: CryptGuardian/core/ai_guardian.py
# Version: 0.1
# Comment: Ai.Gurdian core
import os
from dotenv import load_dotenv
from core.ai_plugins.base import AIPlugin  # Importiere die Basisklasse
from core.ai_plugins.openai_plugin import OpenAIPlugin # Importiere Openai
from core.ai_plugins.claude_plugin import ClaudePlugin # Importiere Claude
from core.ai_plugins.mistral_plugin import MistralPlugin # Importiere Mistral
from core.ai_plugins.llama_plugin import LlamaPlugin # Importiere Llama

# Lädt .env aus Projektroot
load_dotenv()

# Dictionary für initialisierte Plugins
ai_plugins = {}

def use_ai_plugin(name: str):
    """Initialisiert und lädt ein AI-Plugin basierend auf dem Namen"""
    if name in ai_plugins:
        return  # Plugin bereits geladen
        
    if name == "openai":
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY fehlt in .env!")
        ai_plugins[name] = OpenAIPlugin(api_key=api_key)
        
    elif name == "claude":
        api_key = os.getenv("CLAUDE_API_KEY")
        if not api_key:
            raise RuntimeError("CLAUDE_API_KEY fehlt in .env!")
        ai_plugins[name] = ClaudePlugin(api_key=api_key)
        
    elif name == "mistral":
        api_key = os.getenv("MISTRAL_API_KEY")
        if not api_key:
            raise RuntimeError("MISTRAL_API_KEY fehlt in .env!")
        ai_plugins[name] = MistralPlugin(api_key=api_key)
        
    elif name == "llama":
        api_key = os.getenv("REPLICATE_API_TOKEN")
        if not api_key:
            raise RuntimeError("REPLICATE_API_TOKEN fehlt in .env!")
        ai_plugins[name] = LlamaPlugin(api_key=api_key)
        
    else:
        raise ValueError(f"Unbekanntes Plugin: {name}")

def analyze_with(plugin_name: str, prompt: str) -> str:
    """Analysiert einen Prompt mit dem angegebenen Plugin"""
    if plugin_name not in ai_plugins:
        use_ai_plugin(plugin_name)  # Versuche, das Plugin zu laden
    return ai_plugins[plugin_name].analyze(prompt)

def get_available_plugins() -> list:
    """Gibt eine Liste aller verfügbaren Plugin-Namen zurück"""
    return ["openai", "claude", "mistral", "llama"]

def register_plugin(plugin: AIPlugin):
    """Registriert ein benutzerdefiniertes Plugin"""
    ai_plugins[plugin.name()] = plugin
