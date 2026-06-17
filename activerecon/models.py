from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class TargetSpec:
    raw: str
    host: str
    scheme: Optional[str] = None
    port: Optional[int] = None
    path: str = ""
    is_ip: bool = False
    is_private: bool = False
    is_loopback: bool = False


@dataclass
class ReconOptions:
    target: str
    scan_profile: str = "fast"
    output: Optional[str] = None
    output_format: str = "both"
    scope: Optional[str] = None
    dry_run: bool = False
    verbose: bool = False
    quiet: bool = False


@dataclass
class ReconResult:
    target: str
    target_spec: TargetSpec
    scan_profile: str
    markdown_output: Optional[str] = None
    json_output: Optional[str] = None
    results: Dict[str, Any] = field(default_factory=dict)
    dry_run: bool = False
