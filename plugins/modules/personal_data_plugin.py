"""
GÖKTÜRK — Araç İçi Kişisel Veri Koruması Test Modülü (R155 Kategori 6)
Taktik: araç içinde toplanan/saklanan kişisel verinin (yolcu geçmişi,
eşleştirilmiş cihaz bilgisi, konum geçmişi vb.) korunma durumunu İKİ
FARKLI VERİ DURUMUNDA (data state) test eder:

  - telemetry_data_leak               -> R155-6.3 (kişisel veri sızdırma)
    - TRANSIT: backend'e giden telemetri/log akışının anonimleştirme/veri
    minimizasyonu olmadan PII içerip içermediği
  - local_storage_unauthorized_access -> R155-6.10 (araç içinde saklanan
    kişisel veriye yetkisiz erişim) - AT-REST: yerel olarak saklanan
    verinin şifreleme/erişim kontrolü olmadan yerel erişimi olan biri
    tarafından okunabilir olup olmadığı

İkisi de "kişisel veri koruması" temasını paylaşır ama farklı bir veri
durumunu hedefler: biri verinin AKTARILIRKEN, diğeri verinin DURURKEN
korunup korunmadığını sınar — biri ağ/protokol seviyesinde veri
minimizasyonu, diğeri yerel depolama şifrelemesi/erişim kontrolü sorunudur.

Her zafiyetli senaryo, KENDİ R155 vektörüyle AYRI bir Finding olarak
raporlanır (List[Finding]) — böylece her iki vektör de kapsam sayımına
doğru şekilde yansır.
"""

from ..base_plugin import BasePlugin, Finding

_SCENARIOS = {
    "telemetry_data_leak": {
        "vector": "R155-6.3",
        "label": "Telemetri akışında kişisel veri sızıntısı",
        "impact_safety": "none",
        "impact_operational": "low",
        "impact_privacy": "high",
        "cvss": 6.5,
        "remediation": (
            "1. Backend'e gönderilen telemetri/log akışında veri "
            "minimizasyonu uygula; kimliklendirici alanları (konum geçmişi, "
            "cihaz/kullanıcı kimlikleri) toplama noktasında anonimleştir "
            "veya sözde-isimlendir (pseudonymize). "
            "2. Telemetri kanalını uçtan uca şifrele ve yalnızca gerekli "
            "asgari veri kümesini ilet."
        ),
    },
    "local_storage_unauthorized_access": {
        "vector": "R155-6.10",
        "label": "Yerel depoda yetkisiz kişisel veri erişimi",
        "impact_safety": "none",
        "impact_operational": "low",
        "impact_privacy": "high",
        "cvss": 6.2,
        "remediation": (
            "1. Araç içinde saklanan tüm kişisel veriyi (yolculuk geçmişi, "
            "eşleştirilmiş cihaz kayıtları, tercihler) diskte şifrele ve "
            "erişimi rol tabanlı yetkilendirmeyle sınırla. "
            "2. Araç el değiştirdiğinde (satış, kiralama sonu, bakım) "
            "kişisel veriyi güvenli şekilde silen bir 'factory reset' "
            "prosedürü sağla."
        ),
    },
}


class PersonalDataPlugin(BasePlugin):
    module_id = "personal-data-protection"
    name = "Araç İçi Kişisel Veri Koruması"
    surface = "data"
    technique = "data-exposure"
    r155_vector_id = "R155-6.3"   # birincil (koruma aktifse tek özet Finding için)
    r155_category = 6
    avcat_id = "PERSONAL-DATA-EXPOSURE"
    applicable_adapters = ["carla", "simulation"]
    severity_hint = "medium"
    description = (
        "Telemetri akışındaki kişisel veri sızıntısını (R155-6.3, transit) "
        "ve yerel depodaki kişisel veriye yetkisiz erişimi (R155-6.10, "
        "at-rest) ayrı ayrı test eder."
    )

    def run(self, component_config: dict):
        comp_id = component_config.get("id", "unknown")

        try:
            outcomes = {
                scenario: self.adapter.personal_data_probe(comp_id, scenario)
                for scenario in _SCENARIOS
            }
        except NotImplementedError:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                status="inconclusive",
                title="Kişisel Veri Koruması: Adaptör desteklemiyor",
                description=(
                    "Bu test için araç telemetri kanalını ve yerel veri "
                    "deposunu modelleyen bir adaptör gerekli. Gerçek test "
                    "yalnızca yetkili ortamda ve veri sahibinin izniyle "
                    "yapılır."
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
                title="Kişisel Veri Koruması: Transit ve at-rest korumalar aktif",
                description=(
                    "İki kişisel veri koruma senaryosunun tamamı ilgili "
                    "kontrol mekanizması tarafından engellendi:\n\n" + "\n".join(lines)
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
                title=f"Kişisel Veri Koruması: {meta['label']} tespit edildi",
                description=(
                    f"'{comp_id}' üzerinde '{meta['label'].lower()}' senaryosu "
                    f"başarılı oldu: {outcome.get('detail', '')}\n\n"
                    "Kişisel veri koruması eksikliği, GDPR/KVKK gibi veri "
                    "koruma mevzuatı açısından uyumluluk riski taşır ve "
                    "yolcuların/kullanıcıların mahremiyetini doğrudan etkiler."
                ),
                impact_safety=meta["impact_safety"],
                impact_operational=meta["impact_operational"],
                impact_privacy=meta["impact_privacy"],
                attack_feasibility="medium",
                remediation=meta["remediation"],
                cvss_score=meta["cvss"],
            ))
        return findings
