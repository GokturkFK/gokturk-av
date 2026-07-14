"""
GÖKTÜRK — İnsan/Kurumsal Faktörler Test Modülü (R155 Kategori 4)
Taktik: filo operasyonlarının insan/kurumsal faktör kontrollerine üç
senaryo uygular. Bu üçü TEKNİK değil PROSEDÜREL/KURUMSAL kontrollerdir —
bir yazılım zafiyeti değil, bir SÜRECİN var olup olmadığını ve etkili
çalışıp çalışmadığını sınarlar:

  - phishing_susceptibility              → R155-4.1 (sosyal mühendislik/phishing)
    - Personelin/operatörlerin kimlik avına karşı MFA/step-up gibi telafi
    edici bir kontrolü var mı?
  - insecure_default_config               → R155-4.3 (güvensiz varsayılan yapılandırma)
    - Yeni devreye alınan bileşenler sertleştirilmiş bir taban çizgisiyle mi
    yoksa üretici varsayılanlarıyla mı geliyor?
  - operator_misconfiguration_unchecked   → R155-4.5 (operatör tarafından
    hatalı güvenlik yapılandırması)
    - Operatörün güvenlik-kritik bir değişikliği, akran incelemesi/değişiklik
    yönetimi kapısından geçmeden doğrudan uygulanabiliyor mu?

Diğer modüller (backend, OTA, V2X vb.) TEKNİK savunma katmanlarını test
ederken, bu modül bu teknik katmanların ARKASINDAKİ insan ve süreç
katmanını test eder — en güçlü teknik kontrol bile, onu çalıştıran süreç
zayıfsa (phishing'e karşı MFA yok, varsayılan ayarlar değiştirilmiyor,
değişiklikler incelenmiyor) atlanabilir.

Her zafiyetli senaryo, KENDİ R155 vektörüyle AYRI bir Finding olarak
raporlanır (List[Finding]) — böylece üç vektör de kapsam sayımına doğru
şekilde yansır.
"""

from ..base_plugin import BasePlugin, Finding

_SCENARIOS = {
    "phishing_susceptibility": {
        "vector": "R155-4.1",
        "label": "Sosyal mühendislik/phishing'e karşı telafi edici kontrol eksikliği",
        "impact_safety": "medium",
        "impact_operational": "high",
        "impact_privacy": "high",
        "cvss": 7.0,
        "remediation": (
            "1. Tüm personel/operatör hesaplarında çok faktörlü kimlik "
            "doğrulama (MFA) ve hassas işlemler için step-up doğrulama "
            "zorunlu kıl. "
            "2. Düzenli, ölçülen phishing simülasyon kampanyaları ve "
            "güvenlik farkındalık eğitimi programı yürüt."
        ),
    },
    "insecure_default_config": {
        "vector": "R155-4.3",
        "label": "Güvensiz varsayılan yapılandırma",
        "impact_safety": "high",
        "impact_operational": "high",
        "impact_privacy": "medium",
        "cvss": 7.8,
        "remediation": (
            "1. Tüm bileşenler için sertleştirilmiş (hardened) bir dağıtım "
            "taban çizgisi (golden image/config) tanımla ve devreye almayı "
            "bu taban çizgisiyle otomatikleştir. "
            "2. Varsayılan parola/açık debug modu/gereksiz servis kalıp "
            "kalmadığını devreye alma sonrası otomatik olarak denetle "
            "(configuration compliance scanning)."
        ),
    },
    "operator_misconfiguration_unchecked": {
        "vector": "R155-4.5",
        "label": "Operatör yapılandırma değişikliğinin incelemesiz uygulanması",
        "impact_safety": "high",
        "impact_operational": "high",
        "impact_privacy": "medium",
        "cvss": 7.4,
        "remediation": (
            "1. Güvenlik-kritik yapılandırma değişikliklerini (güvenlik "
            "duvarı, loglama, erişim politikaları) akran incelemesi/onay "
            "gerektiren bir değişiklik yönetimi (change management) "
            "sürecinden geçirmeden uygulamayı engelle. "
            "2. Yapılandırma değişikliklerini sürüm kontrollü (infrastructure "
            "as code) ve geri alınabilir (rollback) hale getir; anomali "
            "tespitiyle beklenmeyen değişiklikleri işaretle."
        ),
    },
}


class HumanFactorPlugin(BasePlugin):
    module_id = "human-factor"
    name = "İnsan/Kurumsal Faktörler"
    surface = "human"
    technique = "process-and-policy-gap"
    r155_vector_id = "R155-4.1"   # birincil (koruma aktifse tek özet Finding için)
    r155_category = 4
    avcat_id = "HUMAN-FACTOR-GAP"
    applicable_adapters = ["telematics", "cloud", "simulation"]
    severity_hint = "high"
    description = (
        "Filo operasyonlarının insan/kurumsal faktör kontrollerini — phishing "
        "telafi kontrolü (R155-4.1), güvenli varsayılan yapılandırma "
        "(R155-4.3) ve operatör değişiklik yönetimi (R155-4.5) — ayrı ayrı "
        "test eder."
    )

    def run(self, component_config: dict):
        comp_id = component_config.get("id", "unknown")

        try:
            outcomes = {
                scenario: self.adapter.human_factor_probe(comp_id, scenario)
                for scenario in _SCENARIOS
            }
        except NotImplementedError:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                status="inconclusive",
                title="İnsan/Kurumsal Faktörler: Adaptör desteklemiyor",
                description=(
                    "Bu test için kurumsal süreç/politika durumunu modelleyen "
                    "bir adaptör gerekli. Gerçek değerlendirme, personel "
                    "görüşmeleri ve süreç denetimiyle (audit) birlikte "
                    "yapılmalıdır — bu bulgular yalnızca teknik telafi edici "
                    "kontrollerin varlığını sınar."
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
                title="İnsan/Kurumsal Faktörler: Süreç kontrolleri aktif",
                description=(
                    "Üç insan/kurumsal faktör senaryosunun tamamında ilgili "
                    "süreç/telafi edici kontrol etkili çalışıyor:\n\n" + "\n".join(lines)
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
                title=f"İnsan/Kurumsal Faktörler: {meta['label']}",
                description=(
                    f"'{comp_id}' için '{meta['label'].lower()}' senaryosu "
                    f"zafiyet gösterdi: {outcome.get('detail', '')}\n\n"
                    "Bu bulgu bir yazılım zafiyeti değil, bir SÜRECİN eksik "
                    "veya etkisiz olduğunu gösterir — teknik savunmalar ne "
                    "kadar güçlü olursa olsun, insan/süreç katmanındaki bu "
                    "boşluk saldırgana onları atlama yolu açar."
                ),
                impact_safety=meta["impact_safety"],
                impact_operational=meta["impact_operational"],
                impact_privacy=meta["impact_privacy"],
                attack_feasibility="medium",
                remediation=meta["remediation"],
                cvss_score=meta["cvss"],
            ))
        return findings
