from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List


class RuleFormat(Enum):
    YARA = "yara"
    SIGMA = "sigma"
    WAZUH = "wazuh"


@dataclass
class Rule:
    name: str
    format: RuleFormat
    description: str = ""
    level: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    detection: Dict[str, Any] = field(default_factory=dict)
    condition: str = ""
    strings: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    groups: List[str] = field(default_factory=list)
    if_sid: Optional[str] = None
    if_group: Optional[str] = None
    if_matched_group: Optional[str] = None
    frequency: Optional[int] = None
    timeframe: Optional[str] = None
    mitre: Optional[Dict[str, Any]] = None
    raw: Optional[Any] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "format": self.format.value,
            "description": self.description,
            "level": self.level,
            "metadata": self.metadata,
            "detection": self.detection,
            "condition": self.condition,
            "strings": self.strings,
            "imports": self.imports,
            "groups": self.groups,
            "if_sid": self.if_sid,
            "if_group": self.if_group,
            "if_matched_group": self.if_matched_group,
            "frequency": self.frequency,
            "timeframe": self.timeframe,
            "mitre": self.mitre,
        }
