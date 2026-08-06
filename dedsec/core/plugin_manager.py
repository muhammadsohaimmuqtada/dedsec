import importlib
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional, Tuple

from dedsec.core.module_contract import LEGACY_ENTRYPOINT, RUNTIME_ENTRYPOINT, ModuleMetadata

try:
    from importlib import metadata as importlib_metadata
except ImportError:  # pragma: no cover
    import importlib_metadata  # type: ignore


@dataclass
class PluginRegistration:
    metadata: ModuleMetadata
    import_path: str
    source: str


class PluginManager:
    """Validated plugin registry with explicit diagnostics and entry-point discovery."""

    ENTRY_POINT_GROUP = "dedsec.modules"

    def __init__(self):
        self._plugins: Dict[str, PluginRegistration] = {}
        self._errors: List[Dict[str, str]] = []

    @staticmethod
    def _validate_module(import_path: str):
        module = importlib.import_module(import_path)
        runtime = getattr(module, RUNTIME_ENTRYPOINT, None)
        legacy = getattr(module, LEGACY_ENTRYPOINT, None)
        if not callable(runtime) and not callable(legacy):
            raise ValueError(
                "Plugin %s must expose callable %s or %s"
                % (import_path, RUNTIME_ENTRYPOINT, LEGACY_ENTRYPOINT)
            )
        return module

    def register_plugin(
        self,
        module_key: str,
        import_path: str,
        display_name: str,
        metadata: Optional[ModuleMetadata] = None,
        source: str = "explicit",
    ) -> bool:
        key = (module_key or "").strip().lower()
        if not key:
            raise ValueError("Plugin key cannot be empty")
        if key in self._plugins:
            raise ValueError("Plugin key already registered: %s" % key)
        try:
            module = self._validate_module(import_path)
            declared = metadata or getattr(module, "METADATA", None)
            if declared is None:
                declared = ModuleMetadata(
                    key=key,
                    display_name=display_name,
                    category="plugin",
                    import_path=import_path,
                    impact_class="normal",
                )
            if not isinstance(declared, ModuleMetadata):
                raise TypeError("Plugin METADATA must be a ModuleMetadata instance")
            if declared.key != key:
                raise ValueError("Plugin metadata key does not match registered key")
            self._plugins[key] = PluginRegistration(
                metadata=declared,
                import_path=import_path,
                source=source,
            )
            return True
        except Exception as exc:
            self._errors.append(
                {
                    "key": key,
                    "import_path": import_path,
                    "source": source,
                    "error": "%s: %s" % (exc.__class__.__name__, exc),
                }
            )
            return False

    def discover_entry_points(self) -> int:
        try:
            entry_points = importlib_metadata.entry_points()
            if hasattr(entry_points, "select"):
                candidates = entry_points.select(group=self.ENTRY_POINT_GROUP)
            else:  # Python 3.8 compatibility
                candidates = entry_points.get(self.ENTRY_POINT_GROUP, [])
        except Exception as exc:
            self._errors.append(
                {"key": "*", "import_path": "", "source": "entry-points", "error": str(exc)}
            )
            return 0

        added = 0
        for entry in candidates:
            try:
                module = entry.load()
                import_path = getattr(module, "__name__", None) or str(entry.value)
                declared = getattr(module, "METADATA", None)
                if not isinstance(declared, ModuleMetadata):
                    raise ValueError("Entry-point plugin must expose ModuleMetadata as METADATA")
                if self.register_plugin(
                    declared.key,
                    import_path,
                    declared.display_name,
                    metadata=declared,
                    source="entry-point:%s" % entry.name,
                ):
                    added += 1
            except Exception as exc:
                self._errors.append(
                    {
                        "key": getattr(entry, "name", "unknown"),
                        "import_path": str(getattr(entry, "value", "")),
                        "source": "entry-points",
                        "error": "%s: %s" % (exc.__class__.__name__, exc),
                    }
                )
        return added

    def get_registered_plugins(self) -> Dict[str, Tuple[str, str]]:
        return {
            key: (registration.import_path, registration.metadata.display_name)
            for key, registration in sorted(self._plugins.items())
        }

    def metadata(self) -> Dict[str, Dict[str, object]]:
        return {
            key: asdict(registration.metadata)
            for key, registration in sorted(self._plugins.items())
        }

    def diagnostics(self) -> List[Dict[str, str]]:
        return list(self._errors)
