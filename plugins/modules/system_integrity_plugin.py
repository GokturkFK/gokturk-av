"""
GÖKTÜRK — Sistem Bütünlüğü ve İzolasyon Test Modülü (R155 Kategori 6)
Taktik: compute platformunun bütünlük ve izolasyon sınırlarını ÜÇ farklı
açıdan test eder:

  - edr_tampering                      → R155-6.11 (olay veri kaydı / kara
    kutu manipülasyonu) — kaza öncesi/sonrası telemetrinin yazıldıktan
    SONRA değiştirilip silinemeyeceği (adli veri bütünlüğü)
  - third_party_component_supply_chain → R155-6.12 (tedarik zinciri yazılım
    saldırısı — üçüncü taraf bileşen) — araç içi yazılım yığınına giren
    3. taraf kütüphane/bileşenin imza/SBOM doğrulaması olmadan kabul
    edilip edilmediği
  - hypervisor_container_escape        → R155-6.14 (hipervizör/konteyner
    ortamından kaçış) — izole bir konteyner/VM'in host sisteme veya başka
    bir konteynere kaçışı (izolasyon sınırı)

Firmware Integrity modülü (R155-6.1/6.4/6.13) firmware'in AKTİF olarak
değiştirilip değiştirilemediğini test ederken, third_party_component_
supply_chain senaryosu BUILD/BAĞIMLILIK zincirindeki PASİF doğrulama
eksikliğini (imzasız bir bileşenin sorgusuz kabul edilmesi) hedefler —
biri aktif saldırıyı, diğeri eksik bir kontrolü sınar.

Her zafiyetli senaryo, KENDİ R155 vektörüyle AYRI bir Finding olarak
raporlanır (List[Finding]) — böylece her üç vektör de kapsam sayımına
doğru şekilde yansır.

Bu modülün tamamlanmasıyla proje, yazılımla ulaşılabilecek 55/69 R155
Annex 5 vektörünün TAMAMINA ulaşmış olur.
"""

from ..base_plugin import BasePlugin, Finding

_SCENARIOS = {
    "edr_tampering": {
        "vector": "R155-6.11",
        "label": "Olay veri kaydı (EDR/kara kutu) manipülasyonu",
        "impact_safety": "high",
        "impact_operational": "medium",
        "impact_privacy": "medium",
        "cvss": 6.7,
        "remediation": (
            "1. EDR/kara kutu verisini write-once (WORM) veya kurcalama-"
            "belirgin (tamper-evident) bir depoda tut; yazıldıktan sonra "
            "değiştirilemez/silinemez olsun. "
            "2. Her kayda kriptografik imza/hash zinciri ekle; adli "
            "incelemede bütünlüğün doğrulanabilmesini sağla."
        ),
    },
    "third_party_component_supply_chain": {
        "vector": "R155-6.12",
        "label": "Tedarik zinciri yazılım saldırısı (3. taraf bileşen)",
        "impact_safety": "high",
        "impact_operational": "high",
        "impact_privacy": "low",
        "cvss": 7.9,
        "remediation": (
            "1. Araç içi yazılım build sürecine giren tüm üçüncü taraf "
            "kütüphane/bileşenlerde imza doğrulaması ve SBOM (yazılım "
            "malzeme listesi) eşleşmesini zorunlu kıl. "
            "2. Bağımlılıkları bilinen-iyi (known-good) bir iç ayna/registry "
            "üzerinden çek; doğrudan genel kaynaklardan doğrulamasız çekmeyi "
            "engelle."
        ),
    },
    "hypervisor_container_escape": {
        "vector": "R155-6.14",
        "label": "Hipervizör/konteyner ortamından kaçış",
        "impact_safety": "critical",
        "impact_operational": "high",
        "impact_privacy": "medium",
        "cvss": 8.7,
        "remediation": (
            "1. Hipervizör/konteyner çalışma zamanını (runtime) güncel tut "
            "ve bilinen kaçış zafiyetlerine (CVE) karşı düzenli olarak "
            "tara. "
            "2. Konteynerleri en az ayrıcalıkla (non-root, salt-okunur "
            "dosya sistemi, gereksiz syscall'ları filtreleyen seccomp/"
            "AppArmor profilleri) çalıştır; güvenlik-kritik işlevleri "
            "ayrı, daha güçlü izole donanım bölgelerinde (zonal mimari) tut."
        ),
    },
}


class SystemIntegrityPlugin(BasePlugin):
    module_id = "system-integrity"
    name = "Sistem Bütünlüğü ve İzolasyon"
    surface = "firmware"
    technique = "integrity-and-isolation-boundary"
    r155_vector_id = "R155-6.11"   # birincil (koruma aktifse tek özet Finding için)
    r155_category = 6
    avcat_id = "SYSTEM-INTEGRITY-ISOLATION"
    applicable_adapters = ["socketcan", "carla"]
    severity_hint = "high"
    description = (
        "Olay veri kaydı bütünlüğünü (R155-6.11), üçüncü taraf yazılım "
        "bileşeni tedarik zincirini (R155-6.12) ve hipervizör/konteyner "
        "izolasyon sınırını (R155-6.14) ayrı ayrı test eder."
    )

    def run(self, component_config: dict):
        comp_id = component_config.get("id", "unknown")

        try:
            outcomes = {
                scenario: self.adapter.system_integrity_probe(comp_id, scenario)
                for scenario in _SCENARIOS
            }
        except NotImplementedError:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                status="inconclusive",
                title="Sistem Bütünlüğü: Adaptör desteklemiyor",
                description=(
                    "Bu test için EDR deposunu, yazılım bağımlılık zincirini "
                    "ve hipervizör/konteyner ortamını modelleyen bir adaptör "
                    "gerekli. Gerçek testte fiziksel/yetkili bir tezgâh "
                    "ortamı gerekir."
                ),
            )
        except Exception as e:
            return self.make_error_finding(comp_id, e)

        vulnerable = {s: o for s, o in outcomes.items() if o.get("accepted")}

        if not vulnerable:
            lines = [
                f"  [{meta['vector']}] {meta['label']}: ✓ korumalı — {outcomes[s].get('detail', '')}"
                for s, meta in _SCENARIOS.items()
            ]
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                r155_category=self.r155_category,
                status="not_vulnerable",
                title="Sistem Bütünlüğü: Bütünlük ve izolasyon korumaları aktif",
                description=(
                    "Üç sistem bütünlüğü/izolasyon senaryosunun tamamı ilgili "
                    "koruma mekanizması tarafından engellendi:\n\n" + "\n".join(lines)
                ),
                attack_feasibility="low",
            )

        findings = []
        for scenario, outcome in vulnerable.items():
            meta = _SCENARIOS[scenario]
            findings.append(Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=meta["vector"],
                r155_category=self.r155_category,
                avcat_id=self.avcat_id,
                status="vulnerable",
                title=f"Sistem Bütünlüğü: {meta['label']} başarılı",
                description=(
                    f"'{comp_id}' üzerinde '{meta['label'].lower()}' senaryosu "
                    f"başarılı oldu: {outcome.get('detail', '')}\n\n"
                    "Bütünlük/izolasyon katmanındaki bu boşluk, saldırgana "
                    "adli kanıtı yok etme, güvenilmeyen kod çalıştırma veya "
                    "izolasyon sınırlarını aşarak diğer kritik işlevlere "
                    "sıçrama yeteneği verebilir."
                ),
                impact_safety=meta["impact_safety"],
                impact_operational=meta["impact_operational"],
                impact_privacy=meta["impact_privacy"],
                attack_feasibility="medium",
                remediation=meta["remediation"],
                cvss_score=meta["cvss"],
            ))
        return findings
