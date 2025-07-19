from dataclasses import dataclass, asdict, field
from typing import List, Dict, Optional
import json

@dataclass
class Finding:
    category: str
    name: str
    severity: str
    description: str
    evidence: Optional[str] = None
    mitigation: Optional[str] = None
    references: List[str] = field(default_factory=list)

    def to_dict(self):
        return asdict(self)
    
@dataclass
class Report:
    target: str
    timestamp_utc: str
    findings: List[Finding]
    summary: Dict[str, int]
    metadata: Dict[str, Optional[str]]

    def to_json(self) -> str:
        return json.dumps({
            "target": self.target,
            "timestamp_utc": self.timestamp_utc,
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary,
            "metadata": self.metadata,
        }, indent=2)