"""
GÖKTÜRK — Temel Plugin Sınıfı + Finding Veri Sınıfı
Tüm test modülleri bu sınıfı miras alır.
Yeni saldırı/test = bu sınıfı miras alan yeni bir modül.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
import uuid


@dataclass
class Finding:
    """Test modülünün ürettiği bulgu kaydı.
    
    Her bulgu, R155 taksonomi ID'sine ve ISO 21434 etki boyutlarına bağlıdır.
    Bu sabit şema, bulgu verilerini araç modelinden bağımsız kılar.
    """
    component_id: str
    test_module_id: str
    status: str          # vulnerable / not_vulnerable / inconclusive / error
    title: str

    # Taksonomi bağları
    r155_vector_id: str = ""
    r155_category: Optional[int] = None
    avcat_id: str = ""

    # ISO 21434 Clause 15 — Etki değerlendirmesi (none/low/medium/high/critical)
    impact_safety: str = "none"
    impact_financial: str = "none"
    impact_operational: str = "none"
    impact_privacy: str = "none"

    # ISO 21434 Annex H — Saldırı fizibilitesi
    attack_feasibility: str = "unknown"  # low/medium/high/very_high

    # Detaylar
    description: str = ""
    evidence_paths: List[str] = field(default_factory=list)
    remediation: str = ""
    cvss_score: Optional[float] = None

    # Otomatik alanlar
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def is_vulnerable(self) -> bool:
        return self.status == "vulnerable"

    def is_critical_safety(self) -> bool:
        return self.is_vulnerable() and self.impact_safety in ("high", "critical")

    def highest_impact(self) -> str:
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
        impacts = [self.impact_safety, self.impact_financial,
                   self.impact_operational, self.impact_privacy]
        return max(impacts, key=lambda x: order.get(x, 0))

    def to_dict(self) -> Dict:
        d = {k: v for k, v in self.__dict__.items()}
        return d


class BasePlugin(ABC):
    """Abstract base for all GÖKTÜRK test modules.
    
    Kullanım:
        class MyPlugin(BasePlugin):
            module_id = "my-test"
            ...
            def run(self, component_config: dict) -> Finding:
                ...
    """

    module_id: str = "base"
    name: str = "Temel Plugin"
    surface: str = "unknown"
    technique: str = "unknown"
    r155_vector_id: str = ""
    r155_category: Optional[int] = None
    avcat_id: str = ""
    applicable_adapters: List[str] = []
    severity_hint: str = "medium"
    description: str = ""

    def __init__(self, adapter: Any, config: Optional[Dict[str, Any]] = None):
        self.adapter = adapter
        self.config = config or {}

    @abstractmethod
    def run(self, component_config: Dict[str, Any]) -> Finding:
        """Test mantığını çalıştır, Finding döndür. Asla exception fırlat."""
        pass

    def validate_prerequisites(self) -> Tuple[bool, str]:
        """Ön koşul kontrolü. run() çağrılmadan önce çağrılır."""
        if not self.adapter.is_connected():
            return False, "Adaptör bağlı değil"
        if self.applicable_adapters and self.adapter.adapter_type not in self.applicable_adapters:
            return False, (
                f"Bu modül '{self.adapter.adapter_type}' adaptörünü desteklemiyor. "
                f"Desteklenenler: {self.applicable_adapters}"
            )
        return True, "OK"

    def make_error_finding(self, component_id: str, error: Exception) -> Finding:
        """Hata durumunda standart Finding üret."""
        return Finding(
            component_id=component_id,
            test_module_id=self.module_id,
            r155_vector_id=self.r155_vector_id,
            r155_category=self.r155_category,
            status="error",
            title=f"{self.name}: Hata",
            description=str(error),
        )

    def get_info(self) -> Dict[str, Any]:
        return {
            "module_id": self.module_id,
            "name": self.name,
            "surface": self.surface,
            "technique": self.technique,
            "r155_vector_id": self.r155_vector_id,
            "r155_category": self.r155_category,
            "avcat_id": self.avcat_id,
            "severity_hint": self.severity_hint,
            "applicable_adapters": self.applicable_adapters,
            "description": self.description,
        }
