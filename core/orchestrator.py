"""
GÖKTÜRK — Orchestrator (Çekirdek Motor)
plugins/modules/ altındaki test modüllerini otomatik keşfeder,
verilen araç profilindeki bileşenlere karşı çalıştırır ve bulguları
FindingStore üzerinden kalıcılaştırır.

Çekirdek motor hiçbir zaman aracı doğrudan tanımaz; yalnızca adaptör
arayüzünü ve taksonomiye çapalı Finding şemasını görür.
"""

import importlib
import inspect
import pkgutil
from typing import Any, Dict, List, Optional, Tuple, Type

from plugins.base_plugin import BasePlugin, Finding
from core.finding_store import FindingStore


class Orchestrator:
    def __init__(
        self,
        adapter: Any,
        store: FindingStore,
        plugins_package: str = "plugins.modules",
        strict_adapter: bool = True,
    ):
        self.adapter = adapter
        self.store = store
        self.plugins_package = plugins_package
        # strict_adapter=True → plugin.applicable_adapters ile adaptör tipi eşleşmeli.
        # CI'da mock adaptörle tüm modülleri koşmak için False verilebilir.
        self.strict_adapter = strict_adapter
        self._plugin_classes: Optional[List[Type[BasePlugin]]] = None

    # ── Keşif ────────────────────────────────────────────────────────────────

    def discover_plugin_classes(self) -> List[Type[BasePlugin]]:
        """plugins/modules/ paketindeki tüm BasePlugin alt sınıflarını bulur."""
        classes: List[Type[BasePlugin]] = []
        package = importlib.import_module(self.plugins_package)
        for _, mod_name, _ in pkgutil.iter_modules(package.__path__):
            module = importlib.import_module(f"{self.plugins_package}.{mod_name}")
            for _, obj in inspect.getmembers(module, inspect.isclass):
                if (
                    issubclass(obj, BasePlugin)
                    and obj is not BasePlugin
                    and obj.__module__ == module.__name__
                ):
                    classes.append(obj)

        uniq, seen = [], set()
        for c in sorted(classes, key=lambda c: c.module_id):
            if c.module_id not in seen:
                seen.add(c.module_id)
                uniq.append(c)
        self._plugin_classes = uniq
        return uniq

    def load_plugins(self) -> List[BasePlugin]:
        if self._plugin_classes is None:
            self.discover_plugin_classes()
        return [cls(self.adapter) for cls in (self._plugin_classes or [])]

    # ── Eşleme / ön koşul ────────────────────────────────────────────────────

    def _prereq_ok(self, plugin: BasePlugin) -> Tuple[bool, str]:
        if not self.adapter.is_connected():
            return False, "Adaptör bağlı değil"
        if self.strict_adapter and plugin.applicable_adapters:
            if self.adapter.adapter_type not in plugin.applicable_adapters:
                return False, (
                    f"Adaptör tipi uyumsuz ({self.adapter.adapter_type}); "
                    f"gereken: {plugin.applicable_adapters}"
                )
        return True, "OK"

    def _match_components(self, plugin: BasePlugin, components: List[Dict]) -> List[Dict]:
        """Plugin'i bileşenlere bağlar.

        Taksonomiye çapalı önceliklendirme: önce plugin'in R155 vektörünü
        birebir taşıyan bileşenler aranır (kesin eşleşme). Hiçbir bileşen bu
        vektörü taşımıyorsa, plugin'i tamamen atlamak yerine saldırı yüzeyi
        (surface) üzerinden gevşek bir eşleşmeye düşülür — böylece profil
        henüz o vektörle etiketlenmemiş olsa da plugin en azından ilgili
        yüzeydeki bileşenlerde çalışır. Bu iki aşamalı yaklaşım, "GPS testi
        kameraya da vulnerable etiketi yapıştırıyor" gibi yanlış-pozitif
        genişlemeyi önler.
        """
        if plugin.r155_vector_id:
            vector_matches = [
                c for c in components
                if plugin.r155_vector_id in (c.get("r155_vectors", []) or [])
            ]
            if vector_matches:
                return vector_matches

        if not plugin.surface:
            return []
        return [
            c for c in components
            if any(
                plugin.surface in s or s in plugin.surface
                for s in (c.get("attack_surfaces", []) or [])
            )
        ]

    # ── Çalıştırma ───────────────────────────────────────────────────────────

    def run_all(
        self,
        profile: Dict[str, Any],
        session_notes: str = "",
        persist: bool = True,
    ) -> List[Finding]:
        components = profile.get("components", []) or []
        profile_id = profile.get("id", "unknown")

        session_id = None
        if persist:
            self.store.save_profile(
                profile_id, profile.get("name", profile_id), profile.get("_yaml", "")
            )
            session_id = self.store.create_session(profile_id, session_notes)

        findings: List[Finding] = []
        for plugin in self.load_plugins():
            ok, reason = self._prereq_ok(plugin)

            if ok:
                targets = self._match_components(plugin, components)
                if not targets:  # eşleşen bileşen yoksa sentetik hedefle bir kez koş
                    targets = [{"id": f"auto:{plugin.surface}"}]
            else:
                targets = [{"id": f"skip:{plugin.surface}"}]

            for comp in targets:
                if ok:
                    try:
                        finding = plugin.run(comp)
                    except Exception as e:  # plugin asla exception fırlatmamalı, garanti
                        finding = plugin.make_error_finding(comp.get("id", "unknown"), e)
                else:
                    finding = Finding(
                        component_id=comp.get("id", "unknown"),
                        test_module_id=plugin.module_id,
                        r155_vector_id=plugin.r155_vector_id,
                        r155_category=plugin.r155_category,
                        status="inconclusive",
                        title=f"{plugin.name}: Atlandı",
                        description=reason,
                    )
                findings.append(finding)
                if persist and session_id:
                    self._persist(session_id, profile_id, finding)

        if persist and session_id:
            self.store.close_session(session_id)
        return findings

    def _persist(self, session_id: str, profile_id: str, f: Finding) -> None:
        self.store.add_finding(
            session_id=session_id,
            vehicle_profile_id=profile_id,
            component_id=f.component_id,
            test_module_id=f.test_module_id,
            status=f.status,
            title=f.title,
            r155_vector_id=f.r155_vector_id,
            r155_category=f.r155_category,
            avcat_id=f.avcat_id,
            impact_safety=f.impact_safety,
            impact_financial=f.impact_financial,
            impact_operational=f.impact_operational,
            impact_privacy=f.impact_privacy,
            attack_feasibility=f.attack_feasibility,
            description=f.description,
            evidence_paths=f.evidence_paths,
            remediation=f.remediation,
            cvss_score=f.cvss_score,
        )
