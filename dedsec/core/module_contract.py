from dataclasses import dataclass, field
from typing import List


@dataclass(frozen=True)
class ModuleMetadata:
    key: str
    display_name: str
    category: str
    active: bool = False
    consumes: List[str] = field(default_factory=list)
    produces: List[str] = field(default_factory=list)


RUNTIME_ENTRYPOINT = "run_with_context"
LEGACY_ENTRYPOINT = "run"
