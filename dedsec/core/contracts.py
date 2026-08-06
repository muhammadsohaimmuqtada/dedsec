from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ScanConfig:
    timeout: int = 10
    concurrency: int = 5
    # Hard outer deadline for one module process. A finite default prevents a
    # blocking dependency/socket from holding the scanner indefinitely.
    module_timeout: Optional[int] = 120
    global_timeout: Optional[int] = None
    retries: int = 3
    backoff: float = 0.5
    pool_connections: int = 20
    pool_maxsize: int = 40
    module_retries: int = 1
    retry_backoff_cap: float = 2.0
    circuit_failure_threshold: int = 3
    circuit_cooldown: float = 30.0
    evidence_dir: Optional[str] = None


@dataclass
class TargetInfo:
    url: str
    domain: str
    ip: Optional[str] = None
    ip_list: List[str] = field(default_factory=list)


@dataclass
class PerModuleConfig:
    enabled: bool = True
    timeout: Optional[int] = None
    options: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ModuleResult:
    module: str
    label: str
    status: str
    duration: float
    output: str = ""
    error: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)
    attempts: int = 1
    started_at: Optional[str] = None
    evidence_ids: List[str] = field(default_factory=list)
    failure_class: Optional[str] = None


@dataclass
class ModuleSummary:
    total: int
    successful: int
    failed: int
    timed_out: int
    duration: float
