"""
GÖKTÜRK — Bağlantılı Uygulama Katmanı Test Modülü (R155 Kategori 5)
Taktik: araçla/backend'le konuşan uygulama katmanının güven sınırlarını
İKİ FARKLI KONUMDA test eder:

  - mobile_app_insecure_api          -> R155-5.9 (bağlantılı mobil uygulama
    güvenlik açığı) - araç DIŞINDAKİ uygulama: akıllı telefondaki refakatçi
    (companion) uygulamanın API kimlik doğrulama/token güvenliği
  - third_party_app_privilege_escape -> R155-5.10 (üçüncü taraf IVI
    uygulaması zafiyeti) - araç İÇİNDEKİ uygulama: IVI üzerinde çalışan
    3. taraf uygulamanın sandbox/izin sınırı

İkisi de "uygulama katmanı güveni" temasını paylaşır ama saldırı yüzeyi
farklıdır: biri aracın DIŞINDAN (telefon) API'ye erişimi, diğeri aracın
İÇİNDEN (IVI üzerinde zaten çalışan bir uygulama) kendi sandbox sınırını
aşıp aşamadığını test eder — biri ağ/API güvenliği, diğeri yerel
izolasyon/erişim kontrolü sorunudur.

Her zafiyetli senaryo, KENDİ R155 vektörüyle AYRI bir Finding olarak
raporlanır (List[Finding]) — böylece her iki vektör de kapsam sayımına
doğru şekilde yansır.
"""

from ..base_plugin import BasePlugin, Finding

_SCENARIOS = {
    "mobile_app_insecure_api": {
        "vector": "R155-5.9",
        "label": "Mobil uygulama API güvensizliği",
        "impact_safety": "low",
        "impact_operational": "medium",
        "impact_privacy": "high",
        "cvss": 6.8,
        "remediation": (
            "1. Mobil uygulama ile backend/araç API'si arasında sertifika "
            "pinleme (certificate pinning) ve kısa ömürlü, yenilenebilir "
            "token'lar kullan. "
            "2. API anahtarlarını/sırlarını mobil uygulama ikili dosyasına "
            "gömme; sunucu tarafı yetkilendirme ile değiştir."
        ),
    },
    "third_party_app_privilege_escape": {
        "vector": "R155-5.10",
        "label": "3. taraf IVI uygulaması ayrıcalık aşımı",
        "impact_safety": "medium",
        "impact_operational": "high",
        "impact_privacy": "high",
        "cvss": 7.3,
        "remediation": (
            "1. IVI işletim sisteminde uygulama sandbox'ını sıkılaştır; her "
            "uygulamayı yalnızca beyan ettiği izin kapsamıyla sınırla "
            "(ör. Android Automotive izin modeli). "
            "2. Araç-kritik API'lere (CAN/ROS2 köprüsü, konum, teşhis) erişimi "
            "yalnızca imzalı/onaylı ilk taraf uygulamalarla sınırla."
        ),
    },
}


class AppLayerPlugin(BasePlugin):
    module_id = "app-layer"
    name = "Bağlantılı Uygulama Katmanı"
    surface = "ivi"
    technique = "privilege-boundary-bypass"
    r155_vector_id = "R155-5.9"   # birincil (koruma aktifse tek özet Finding için)
    r155_category = 5
    avcat_id = "APP-LAYER-TRUST"
    applicable_adapters = ["carla", "simulation"]
    severity_hint = "medium"
    description = (
        "Mobil refakatçi uygulamanın API güvenliğini (R155-5.9) ve IVI "
        "üzerinde çalışan üçüncü taraf uygulamanın sandbox/izin sınırını "
        "(R155-5.10) ayrı ayrı test eder."
    )

    def run(self, component_config: dict):
        comp_id = component_config.get("id", "unknown")

        try:
            outcomes = {
                scenario: self.adapter.app_layer_probe(comp_id, scenario)
                for scenario in _SCENARIOS
            }
        except NotImplementedError:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                status="inconclusive",
                title="Uygulama Katmanı: Adaptör desteklemiyor",
                description=(
                    "Bu test için mobil uygulama/IVI uygulama çatısını "
                    "modelleyen bir adaptör gerekli. Gerçek test yalnızca "
                    "yetkili ortamda yapılır."
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
                title="Uygulama Katmanı: Güven sınırları korunuyor",
                description=(
                    "İki uygulama katmanı senaryosunun tamamı ilgili kontrol "
                    "mekanizması tarafından engellendi:\n\n" + "\n".join(lines)
                ),
                attack_feasibility="high",
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
                title=f"Uygulama Katmanı: {meta['label']} başarılı",
                description=(
                    f"'{comp_id}' üzerinde '{meta['label'].lower()}' senaryosu "
                    f"başarılı oldu: {outcome.get('detail', '')}\n\n"
                    "Uygulama katmanındaki güven sınırı ihlalleri, saldırgana "
                    "araç/backend API'sine veya araç içi kritik veriye "
                    "protokol seviyesindeki savunmaları hiç görmeden erişim "
                    "sağlayabilir."
                ),
                impact_safety=meta["impact_safety"],
                impact_operational=meta["impact_operational"],
                impact_privacy=meta["impact_privacy"],
                attack_feasibility="medium",
                remediation=meta["remediation"],
                cvss_score=meta["cvss"],
            ))
        return findings
