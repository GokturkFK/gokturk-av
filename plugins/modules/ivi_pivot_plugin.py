"""
GÖKTÜRK — IVI / Infotainment Üzerinden Pivot Test Modülü (R155 Kategori 5)
Taktik: IVI/infotainment sistemi (veya ona besleyen yolcu WiFi AP'si) ele
geçirildikten sonra, araç içi kritik ağlara (CAN/gateway) pivot yapılıp
yapılamadığını test eder.

Bu, klasik "zayıf halka" senaryosudur: infotainment genelde en az
kısıtlanmış, en çok üçüncü taraf uygulama çalıştıran alt sistemdir; ondan
kritik ağlara sızma, yeterli ağ ayrıştırması (segmentation) olmadığında
mümkün olur. Saha araştırmasındaki 2015 Jeep Cherokee vakasının bir
varyantı — orada pivot TCU üzerinden olmuştu (R155-5.13), burada pivot
IVI/yolcu bağlanabilirliği üzerinden test edilir.

R155-5.4: IVI / infotainment üzerinden pivot
"""

from ..base_plugin import BasePlugin, Finding


class IVIPivotPlugin(BasePlugin):
    module_id = "ivi-pivot"
    name = "IVI / Infotainment Üzerinden Pivot"
    surface = "ivi"
    technique = "network-pivot"
    r155_vector_id = "R155-5.4"
    r155_category = 5
    avcat_id = "IVI-PIVOT"
    applicable_adapters = ["socketcan", "carla"]
    severity_hint = "high"
    description = (
        "IVI/infotainment sisteminin ele geçirilmesi sonrası araç içi kritik "
        "ağlara (CAN/gateway) pivot yapılıp yapılamadığını, ağ ayrıştırma "
        "(segmentation) etkinliğini ölçerek test eder."
    )

    def run(self, component_config: dict) -> Finding:
        comp_id = component_config.get("id", "unknown")

        try:
            pivoted = self.adapter.ivi_pivot_probe(comp_id)
        except NotImplementedError:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                status="inconclusive",
                title="IVI Pivot: Adaptör desteklemiyor",
                description=(
                    "Bu test için IVI/gateway ağ topolojisini modelleyen bir "
                    "adaptör gerekli. Gerçek testte izole bir tezgâh ortamında "
                    "yapılmalıdır."
                ),
            )
        except Exception as e:
            return self.make_error_finding(comp_id, e)

        if pivoted:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                r155_category=self.r155_category,
                avcat_id=self.avcat_id,
                status="vulnerable",
                title="IVI Pivot: Kritik ağa sızma başarılı",
                description=(
                    f"'{comp_id}' üzerinden ele geçirilen IVI/bağlanabilirlik "
                    "yüzeyinden, araç içi kritik ağa (CAN/gateway) yeterli "
                    "ayrıştırma olmadan pivot yapılabildi.\n\n"
                    "IVI/infotainment genelde en az kısıtlanmış, üçüncü taraf "
                    "uygulama çalıştıran alt sistemdir — bu yüzden 'zayıf "
                    "halka' olarak sıkça istismar edilir. Yeterli ağ "
                    "ayrıştırması olmadan, bu yüzeyden ele geçirme doğrudan "
                    "güvenlik-kritik CAN mesajlarına (fren, direksiyon) "
                    "erişimle sonuçlanabilir."
                ),
                impact_safety="high",
                impact_operational="high",
                attack_feasibility="medium",
                remediation=(
                    "1. IVI'yi ayrı bir ağ zonuna (VLAN/domain) al; kritik CAN "
                    "ağıyla arasına tek yönlü veya sıkı filtrelemeli bir "
                    "gateway koy. "
                    "2. IVI'den gelen mesajları gateway'de allowlist ile "
                    "sınırla — yalnızca beklenen, zararsız komutlara izin ver. "
                    "3. IVI üzerinde çalışan üçüncü taraf uygulamaları "
                    "sandboxing ile izole et. "
                    "4. Periyodik güvenlik değerlendirmesiyle IVI-gateway "
                    "sınırının etkinliğini doğrula."
                ),
                cvss_score=7.8,
            )

        return Finding(
            component_id=comp_id,
            test_module_id=self.module_id,
            r155_vector_id=self.r155_vector_id,
            status="not_vulnerable",
            title="IVI Pivot: Ağ ayrıştırması etkili",
            description=(
                f"'{comp_id}' üzerinden kritik ağa pivot denemesi başarısız "
                "oldu; ağ ayrıştırması/gateway filtrelemesi etkili görünüyor."
            ),
            attack_feasibility="low",
        )
