"""
GÖKTÜRK — OBD-II / UDS Teşhis Enumerasyon Modülü
Taktik: OBD-II portu üzerinden UDS (ISO 14229) servislerini yoklar;
teşhis oturumu açıldıktan sonra güvenlik-kritik servislerin (security
access, write data, routine, request download) kimlik doğrulaması
olmadan erişilebilir olup olmadığını tespit eder.

R155-5.5: OBD-II teşhis portu istismarı
"""

from ..base_plugin import BasePlugin, Finding

# UDS servis kimlikleri
UDS_SESSION_CONTROL = 0x10
UDS_SENSITIVE = {
    0x27: "SecurityAccess (0x27)",
    0x2E: "WriteDataByIdentifier (0x2E)",
    0x31: "RoutineControl (0x31)",
    0x34: "RequestDownload (0x34)",
}


class OBD2EnumPlugin(BasePlugin):
    module_id = "obd2-enum"
    name = "OBD-II / UDS Servis Enumerasyonu"
    surface = "diagnostic"
    technique = "enumeration"
    r155_vector_id = "R155-5.5"
    r155_category = 5
    avcat_id = "DIAG-UDS-ENUM"
    applicable_adapters = ["socketcan", "carla"]
    severity_hint = "high"
    description = (
        "OBD-II/UDS üzerinden teşhis servislerini yoklar ve güvenlik-kritik "
        "servislerin kimlik doğrulaması olmadan erişilebilirliğini ölçer."
    )

    @staticmethod
    def _is_positive(resp: bytes, sid: int) -> bool:
        return bool(resp) and resp[0] == (sid + 0x40)

    def run(self, component_config: dict) -> Finding:
        comp_id = component_config.get("id", "unknown")

        try:
            # 1. Genişletilmiş teşhis oturumu açmayı dene
            session = self.adapter.uds_request(UDS_SESSION_CONTROL, 0x03)
        except NotImplementedError:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                status="inconclusive",
                title="OBD-II Enum: Adaptör UDS desteklemiyor",
                description="Bu test için SocketCAN/CARLA (UDS yetenekli) adaptör gerekli.",
            )
        except Exception as e:
            return self.make_error_finding(comp_id, e)

        if not session:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                status="inconclusive",
                title="OBD-II Enum: Teşhis oturumu açılamadı",
                description=(
                    "OBD-II portu üzerinden UDS yanıtı alınamadı. "
                    "Port fiziksel olarak erişilebilir mi, ECU cevap veriyor mu?"
                ),
                attack_feasibility="unknown",
            )

        # 2. Güvenlik-kritik servisleri yokla
        exposed = []
        for sid, label in UDS_SENSITIVE.items():
            try:
                resp = self.adapter.uds_request(sid, 0x01)
            except Exception:
                resp = None
            if resp and self._is_positive(resp, sid):
                exposed.append(label)

        if exposed:
            exposed_list = "\n".join(f"  ⚠ {s}" for s in exposed)
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                r155_category=self.r155_category,
                avcat_id=self.avcat_id,
                status="vulnerable",
                title=f"OBD-II Enum: {len(exposed)} kritik UDS servisi korumasız",
                description=(
                    "Genişletilmiş teşhis oturumu açıldı ve aşağıdaki güvenlik-kritik "
                    "servisler uygun kimlik doğrulaması olmadan pozitif yanıt verdi:\n\n"
                    f"{exposed_list}\n\n"
                    "Bu servisler firmware yazma, rutin çalıştırma ve güvenlik erişimi "
                    "gibi yüksek etkili işlemleri mümkün kılar."
                ),
                impact_safety="high",
                impact_operational="high",
                impact_financial="medium",
                attack_feasibility="medium",
                remediation=(
                    "1. SecurityAccess (0x27) için güçlü seed/key (kısa değil, tekrar "
                    "kullanılmayan) ve deneme sınırlaması uygula. "
                    "2. 0x2E/0x31/0x34 servislerini yalnızca kilit açıldıktan sonra izin ver. "
                    "3. OBD-II erişimini gateway'de rol/oturum bazlı yetkilendir. "
                    "4. Teşhis erişimlerini logla ve anormal erişimde alarm üret."
                ),
                cvss_score=7.8,
            )

        return Finding(
            component_id=comp_id,
            test_module_id=self.module_id,
            r155_vector_id=self.r155_vector_id,
            r155_category=self.r155_category,
            status="not_vulnerable",
            title="OBD-II Enum: Kritik servisler korumalı",
            description=(
                "Teşhis oturumu açıldı ancak güvenlik-kritik UDS servisleri kimlik "
                "doğrulaması olmadan erişime kapalı (negatif yanıt). Erişim kontrolü "
                "çalışıyor görünüyor."
            ),
            attack_feasibility="high",
        )
