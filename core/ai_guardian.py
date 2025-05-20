# core/ai_guardian.py

from core.ai_plugins.openai_plugin import OpenAIPlugin
# von anderen Plugins: from core.ai_plugins.mistral_plugin import ...

ai_plugins = {}

def use_ai_plugin(name: str, **kwargs):
    if name == "openai":
        ai_plugins[name] = OpenAIPlugin(api_key=kwargs.get("api_key"))
    # elif name == "claude": ...
    else:
        raise ValueError(f"Plugin {name} nicht verfügbar.")

def analyze_with(plugin_name: str, prompt: str) -> str:
    if plugin_name not in ai_plugins:
        raise RuntimeError(f"Plugin {plugin_name} nicht initialisiert.")
    return ai_plugins[plugin_name].analyze(prompt)
