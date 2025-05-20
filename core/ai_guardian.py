# core/ai_guardian.py

import os
from dotenv import load_dotenv
from core.ai_plugins.openai_plugin import OpenAIPlugin
# weitere Plugins...

load_dotenv()  # lädt .env aus Projektroot

ai_plugins = {}

def use_ai_plugin(name: str):
    if name == "openai":
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY fehlt in .env!")
        ai_plugins[name] = OpenAIPlugin(api_key=api_key)

    # Beispiel für Claude, Mistral usw. folgt ... 

def analyze_with(plugin_name: str, prompt: str) -> str:
    if plugin_name not in ai_plugins:
        raise RuntimeError(f"Plugin {plugin_name} nicht initialisiert.")
    return ai_plugins[plugin_name].analyze(prompt)
