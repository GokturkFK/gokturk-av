"""
GÖKTÜRK — Teşhis Erişimi Suistimali Test Modülü (R155 Kategori 4)
Taktik: zaten meşru/açık bir teşhis oturumu (ör. yetkili tamirci bağlantısı)
üzerinden, oturumun amaçlanan kapsamını aşan bir işlem (güvenlik-kritik
parametre yazma veya kapsam-dışı toplu veri çekme) denenir.

obd2-enum (R155-5.5) DIŞ, kimlik doğrulamasız erişimi test ederken; bu modül
İÇERİDEN/YETKİLİ kullanıcının kapsam suistimalini test eder — R155 Annex 5'in
"istenmeyen insan davranışları" kategorisinin tam karşılığı: teknik bir dış
saldırı değil, meşru erişimin kötüye kullanılmasıdır.

R155-4.2: Meşru teşhis erişiminin kötüye kullanımı
"""

from ..base_plugin import BasePlugin, Finding

_ACTION_LABELS = {
    "write_critical_param": "Güvenlik-kritik parametre yazma",
    "bulk_extract": "Kapsam-dışı toplu veri çekme",
}


class DiagnosticAccessAbusePlugin(BasePlugin):
    module_id = "diag-access-abuse"
    name = "Teşhis Erişimi Suistimali"
    surface = "diagnostic"
    technique = "privilege-abuse"
    r155_vector_id = "R155-4.2"
    r155_category = 4
    avcat_id = "DIAG-SCOPE-ABUSE"
    applicable_adapters = ["socketcan", "carla"]
    severity_hint = "medium"
    description = (
        "Zaten açık/meşru bir teşhis oturumunun kapsamını aşan işlemlere "
        "(güvenlik-kritik parametre yazma, toplu veri çekme) karşı kapsam "
        "sınırlaması ve denetim (audit) kontrolünün etkinliğini test eder."
    )

    DEFAULT_ACTION = "write_critical_param"

    def run(self, component_config: dict) -> Finding:
        comp_id = component_config.get("id", "unknown")
        action = str(self.config.get("diag_action", self.DEFAULT_ACTION))
        action_label = _ACTION_LABELS.get(action, action)

        try:
            allowed = self.adapter.diagnostic_scope_probe(comp_id, action=action)
        except NotImplementedError:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                status="inconclusive",
                title="Teşhis Erişimi Suistimali: Adaptör desteklemiyor",
                description=(
                    "Bu test için teşhis oturumu kapsam kontrolünü modelleyen "
                    "bir adaptör gerekli. Gerçek testte yetkili bir teşhis "
                    "oturumu (ör. bayi/tamirci erişimi) simüle edilmelidir."
                ),
            )
        except Exception as e:
            return self.make_error_finding(comp_id, e)

        if allowed:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                r155_category=self.r155_category,
                avcat_id=self.avcat_id,
                status="vulnerable",
                title=f"Teşhis Erişimi Suistimali: Kapsam sınırlaması yok ({action_label})",
                description=(
                    f"'{comp_id}' üzerinde açık bir teşhis oturumu, "
                    f"'{action_label.lower()}' işlemini ek yetkilendirme veya "
                    "denetim (audit log) olmadan kabul etti.\n\n"
                    "Bu bir dış saldırı değil, meşru erişimin (yetkili "
                    "personel, bayi, tamirci) kapsamını aşan kullanımıdır. "
                    "Kapsam sınırlaması ve işlem denetimi olmadan, tek bir "
                    "yetkili oturum güvenlik-kritik parametreleri değiştirebilir "
                    "veya amaçlanandan çok daha fazla veri çekebilir."
                ),
                impact_safety="medium",
                impact_operational="medium",
                impact_privacy="medium",
                attack_feasibility="high",
                remediation=(
                    "1. Teşhis oturumlarında görev-bazlı kapsam sınırlaması "
                    "(role-based scope restriction) uygula — her oturum yalnızca "
                    "amaçlanan işlemlere izin vermeli. "
                    "2. Güvenlik-kritik parametre yazımlarında ikinci bir "
                    "yetkilendirme adımı (ör. üretici onayı/imzalı komut) ekle. "
                    "3. Tüm teşhis oturumu işlemlerini değiştirilemez şekilde "
                    "denetim kaydına (audit log) yaz. "
                    "4. Bayi/tamirci erişim yetkilerini düzenli olarak gözden "
                    "geçir ve en az yetki ilkesini uygula."
                ),
                cvss_score=5.4,
            )

        return Finding(
            component_id=comp_id,
            test_module_id=self.module_id,
            r155_vector_id=self.r155_vector_id,
            status="not_vulnerable",
            title=f"Teşhis Erişimi Suistimali: Kapsam sınırlaması aktif ({action_label})",
            description=(
                f"'{comp_id}' üzerindeki teşhis oturumu, '{action_label.lower()}' "
                "işlemini kapsam sınırlaması veya denetim kontrolüyle engelledi/"
                "kaydetti."
            ),
            attack_feasibility="medium",
        )
