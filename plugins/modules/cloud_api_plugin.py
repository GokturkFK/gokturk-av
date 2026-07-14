"""
GÖKTÜRK — Araç-Bulut API Yetkisiz Erişimi Test Modülü (R155 Kat.5)
Taktik: aracın bulut/backend API'siyle konuşurken NESNE DÜZEYİNDE
yetkilendirme (object-level authorization) sınırını test eder.

Backend Server modülünün weak_auth senaryosu (R155-1.1) personel/yönetici
erişimini hedeflerken, bu modül ARAÇ-BULUT (machine-to-machine) API'sinin
kendisini hedefler: geçerli bir aracın kimlik bilgileriyle BAŞKA bir aracın
verisine/komutuna erişilip erişilemediğini sınar — biri İNSAN kimlik
doğrulamasını, diğeri MAKİNELER ARASI yetkilendirme sınırını (bir aracın
kimliği diğerinin kapsamına taşabiliyor mu?) test eder.

R155-5.11: Araç-Bulut API yetkisiz erişimi
"""

from ..base_plugin import BasePlugin, Finding

_METHOD_LABELS = {
    "cross_vehicle_bola": "Araçlar arası nesne düzeyinde yetkilendirme aşımı (BOLA)",
    "unauthenticated_device_binding": "Cihaz sertifika bağlaması olmadan araç-kapsamlı erişim",
}


class CloudAPIPlugin(BasePlugin):
    module_id = "cloud-api-access"
    name = "Araç-Bulut API Yetkisiz Erişimi"
    surface = "telematics"
    technique = "broken-object-level-authorization"
    r155_vector_id = "R155-5.11"
    r155_category = 5
    avcat_id = "CLOUD-API-BOLA"
    applicable_adapters = ["telematics", "cloud", "simulation"]
    severity_hint = "high"
    description = (
        "Aracın bulut/backend API'sinde nesne düzeyinde yetkilendirmeyi "
        "(bir aracın kimlik bilgileriyle başka bir aracın verisine/komutuna "
        "erişilip erişilemediğini) test eder."
    )

    DEFAULT_METHOD = "cross_vehicle_bola"

    def run(self, component_config: dict) -> Finding:
        comp_id = component_config.get("id", "unknown")
        method = str(self.config.get("cloud_api_method", self.DEFAULT_METHOD))
        method_label = _METHOD_LABELS.get(method, method)

        try:
            accessible = self.adapter.cloud_api_probe(comp_id, method=method)
        except NotImplementedError:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                status="inconclusive",
                title="Araç-Bulut API: Adaptör desteklemiyor",
                description=(
                    "Bu test için araç-bulut API'sini modelleyen bir adaptör "
                    "gerekli. Gerçek testte fiziksel/yetkili bir ortam ve "
                    "servis sahibinin izni gerekir."
                ),
            )
        except Exception as e:
            return self.make_error_finding(comp_id, e)

        if accessible:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                r155_category=self.r155_category,
                avcat_id=self.avcat_id,
                status="vulnerable",
                title=f"Araç-Bulut API: Yetkisiz erişim başarılı ({method_label})",
                description=(
                    f"'{comp_id}' üzerinden erişilen araç-bulut API'sinde "
                    f"'{method_label.lower()}' senaryosu başarılı oldu; "
                    "geçerli bir aracın kimlik bilgileri veya isteği, "
                    "BAŞKA bir aracın verisine/komutuna erişim sağladı.\n\n"
                    "Filo homojenliği düşünüldüğünde bu, tek bir aracın "
                    "ele geçirilmesinin filodaki DİĞER araçların verisine/"
                    "kontrolüne sıçramasına olanak tanıyabilir — 'bir aracı "
                    "ele geçir, hepsine eriş' senaryosu."
                ),
                impact_safety="high",
                impact_operational="high",
                impact_financial="medium",
                impact_privacy="high",
                attack_feasibility="medium",
                remediation=(
                    "1. Her API isteğinde nesne düzeyinde yetkilendirme "
                    "kontrolü (object-level authorization check) zorunlu kıl: "
                    "istekte belirtilen araç kimliği, isteği yapan kimlik "
                    "bilgisinin GERÇEKTEN sahip olduğu araçla eşleşmeli. "
                    "2. Her araç için benzersiz bir cihaz sertifikası/anahtar "
                    "çifti kullan ve API'nin isteği bu sertifikaya bağlamasını "
                    "(device binding) zorunlu kıl. "
                    "3. Düzenli yetkilendirme testleri (ör. OWASP API "
                    "Security Top 10 — BOLA) CI güvenlik hattına dahil et."
                ),
                cvss_score=8.2,
            )

        return Finding(
            component_id=comp_id,
            test_module_id=self.module_id,
            r155_vector_id=self.r155_vector_id,
            status="not_vulnerable",
            title=f"Araç-Bulut API: Nesne düzeyinde yetkilendirme korumalı ({method_label})",
            description=(
                f"'{comp_id}' üzerindeki araç-bulut API'sinde "
                f"({method_label.lower()}) nesne düzeyinde yetkilendirme/"
                "cihaz kimlik bağlaması etkin; araçlar arası yetkisiz "
                "erişim engellendi."
            ),
            attack_feasibility="low",
        )
