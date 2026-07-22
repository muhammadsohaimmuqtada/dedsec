import importlib
from typing import Dict, Any, List

class PluginManager:
    """
    Dynamically loads and registers custom DEDSEC modules at runtime.
    """

    def __init__(self):
        self.plugins = {}

    def register_plugin(self, module_key: str, import_path: str, display_name: str):
        try:
            mod = importlib.import_module(import_path)
            if hasattr(mod, "run"):
                self.plugins[module_key] = (import_path, display_name)
                return True
        except Exception:
            pass
        return False

    def get_registered_plugins(self) -> Dict[str, tuple]:
        return self.plugins
