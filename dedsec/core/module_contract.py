from dataclasses import dataclass, field
from typing import List, Optional


IMPACT_CLASSES = (
    "passive",
    "normal",
    "active-safe",
    "state-changing",
    "high-impact",
)


@dataclass(frozen=True)
class ModuleMetadata:
    key: str
    display_name: str
    category: str
    import_path: Optional[str] = None
    impact_class: str = "normal"
    active: bool = False
    requires_target_http: bool = False
    requires_auth: bool = False
    requires_browser: bool = False
    state_mutation: bool = False
    protocols: List[str] = field(default_factory=list)
    consumes: List[str] = field(default_factory=list)
    produces: List[str] = field(default_factory=list)

    def __post_init__(self):
        if self.impact_class not in IMPACT_CLASSES:
            raise ValueError("Unsupported module impact class: %s" % self.impact_class)
        if self.state_mutation and self.impact_class not in {"state-changing", "high-impact"}:
            raise ValueError("State-mutating modules must declare state-changing or high-impact")


RUNTIME_ENTRYPOINT = "run_with_context"
LEGACY_ENTRYPOINT = "run"
