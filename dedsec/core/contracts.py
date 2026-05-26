from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class ScanConfig:
    timeout: int = 10
    module_timeout: Optional[int] = None
    global_timeout: Optional[int] = None
    concurrency: int = 5
    retries: int = 3
    backoff: float = 0.5
    pool_connections: int = 20
    pool_maxsize: int = 40


@dataclass
class ModuleResult:
    module: str
    label: str
    status: str
    duration: float = 0.0
    result: Dict[str, Any] = field(default_factory=dict)
    output: str = ""
    error: Optional[str] = None
