"""
GÖKTÜRK — Harici Cihaz Bağlantı Erişimi Test Modülü (R155 Kat.4 + Kat.5)
Taktik: IVI/kabin bağlantı merkezinin harici cihaz erişim kontrollerine
üç senaryo uygular; her biri FARKLI bir katmanı ve FARKLI bir R155
kategorisini hedefler:

  - bluetooth_pairing_bypass -> R155-5.2 (Bluetooth / kısa mesafeli
    kablosuz saldırı) - PROTOKOL katmanı: eşleştirme kimlik doğrulaması
  - usb_autorun_exploit      -> R155-5.3 (USB / fiziksel port saldırısı)
    - PROTOKOL katmanı: USB autorun/autoexec koruması
  - rogue_device_enrollment  -> R155-4.4 (iç tehdit: yetkisiz harici cihaz
    bağlantısı) - KURUMSAL/POLİTİKA katmanı: filo yönetim politikasının
    (operatör onayı, denetim) kanaldan bağımsız olarak uygulanıp
    uygulanmadığı

İlk ikisi "protokol güvenli mi?" sorusuna cevap verirken, üçüncüsü
"protokol güvenli olsa bile, kurumun cihaz kaydı için bir onay/denetim
süreci var mı?" sorusuna cevap verir - biri teknik, diğeri organizasyonel
bir kontrol olduğu için ikisi de gerekli ve birbirinin yerini tutmaz.

Her zafiyetli senaryo, KENDİ R155 vektörü ve KENDİ kategorisiyle AYRI bir
Finding olarak raporlanır (List[Finding]) - üç vektör de kapsam sayımına
doğru şekilde yansır.
"""

from ..base_plugin import BasePlugin, Finding

_SCENARIOS = {
    "bluetooth_pairing_bypass": {
        "vector": "R155-5.2",
        "category": 5,
        "label": "Bluetooth eşleştirme atlatma",
        "impact_safety": "low",
        "impact_operational": "medium",
        "impact_privacy": "high",
        "cvss": 6.1,
        "remediation": (
            "1. Bluetooth eşleştirmesinde kullanıcı onayı ve güçlü PIN/passkey "
            "doğrulamasını zorunlu kıl (Secure Simple Pairing, Just Works modunu "
            "kritik profillerde devre dışı bırak). "
            "2. Eşleştirilen cihaz listesini periyodik olarak denetle ve "
            "kullanılmayan eşleştirmeleri otomatik sonlandır."
        ),
    },
    "usb_autorun_exploit": {
        "vector": "R155-5.3",
        "category": 5,
        "label": "USB autorun istismarı",
        "impact_safety": "medium",
        "impact_operational": "high",
        "impact_privacy": "medium",
        "cvss": 7.0,
        "remediation": (
            "1. USB üzerinden takılan cihazlarda autorun/autoexec'i tamamen "
            "devre dışı bırak; bilinmeyen depolama cihazlarını salt-okunur "
            "monte et. "
            "2. USB cihaz sınıfı beyaz listesi uygula (ör. yalnızca "
            "onaylanmış güncelleme aracı sınıfına izin ver)."
        ),
    },
    "rogue_device_enrollment": {
        "vector": "R155-4.4",
        "category": 4,
        "label": "Yetkisiz harici cihaz kaydı (politika ihlali)",
        "impact_safety": "medium",
        "impact_operational": "high",
        "impact_privacy": "high",
        "cvss": 6.4,
        "remediation": (
            "1. Filo yönetim politikasında yeni cihaz kaydı için operatör "
            "onayı ve denetim (audit) kaydı zorunlu kıl - kanaldan (BT/USB/vb.) "
            "bağımsız olarak uygula. "
            "2. Kayıtlı cihaz envanterini merkezi bir filo yönetim sisteminde "
            "tut ve düzenli mutabakat (reconciliation) yap."
        ),
    },
}


class ExternalDeviceAccessPlugin(BasePlugin):
    module_id = "external-device-access"
    name = "Harici Cihaz Bağlantı Erişimi"
    surface = "ivi"
    technique = "unauthorized-pairing"
    r155_vector_id = "R155-5.2"
    r155_category = 5
    avcat_id = "EXT-DEVICE-ACCESS"
    applicable_adapters = ["carla", "simulation"]
    severity_hint = "medium"
    description = (
        "IVI/kabin bağlantı merkezinin Bluetooth eşleştirme (R155-5.2), USB "
        "autorun (R155-5.3) ve filo politikası cihaz kaydı (R155-4.4) "
        "kontrollerini ayrı ayrı test eder."
    )

    def run(self, component_config: dict):
        comp_id = component_config.get("id", "unknown")

        try:
            outcomes = {
                scenario: self.adapter.external_device_probe(comp_id, scenario)
                for scenario in _SCENARIOS
            }
        except NotImplementedError:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                status="inconclusive",
                title="Harici Cihaz Erişimi: Adaptör desteklemiyor",
                description=(
                    "Bu test için IVI/kabin bağlantı arayüzünü modelleyen bir "
                    "adaptör gerekli. Gerçek testte fiziksel/yetkili bir araç "
                    "ortamı gerekir."
                ),
            )
        except Exception as e:
            return self.make_error_finding(comp_id, e)

        vulnerable = {s: o for s, o in outcomes.items() if o.get("accepted")}

        if not vulnerable:
            lines = [
                f"  [{meta['vector']}] {meta['label']}: ✓ korumalı - {outcomes[s].get('detail', '')}"
                for s, meta in _SCENARIOS.items()
            ]
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                r155_category=self.r155_category,
                status="not_vulnerable",
                title="Harici Cihaz Erişimi: Protokol ve politika kontrolleri aktif",
                description=(
                    "Üç harici cihaz erişim senaryosunun tamamı ilgili kontrol "
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
                r155_category=meta["category"],
                avcat_id=self.avcat_id,
                status="vulnerable",
                title=f"Harici Cihaz Erişimi: {meta['label']} başarılı",
                description=(
                    f"'{comp_id}' üzerinde '{meta['label'].lower()}' senaryosu "
                    f"başarılı oldu: {outcome.get('detail', '')}\n\n"
                    "Yetkisiz harici cihaz erişimi, saldırgana araç kabinine "
                    "fiziksel/yakın-mesafe erişimi olduğunda ek bir pivot "
                    "noktası ve veri sızıntı kanalı sağlar."
                ),
                impact_safety=meta["impact_safety"],
                impact_operational=meta["impact_operational"],
                impact_privacy=meta["impact_privacy"],
                attack_feasibility="medium",
                remediation=meta["remediation"],
                cvss_score=meta["cvss"],
            ))
        return findings
