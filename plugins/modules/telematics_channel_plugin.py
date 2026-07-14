"""
GÖKTÜRK — Telematik Kanalı İstismarı Test Modülü (R155 Kategori 5)
Taktik: hücresel/WiFi telematik kanalının bağlantı katmanına yönelik bir
istismar dener — zayıf/eski şifreleme, sahte baz istasyonu/erişim noktası
kabulü veya kanal üzerinde dinleme/enjeksiyon.

Bu, projedeki diğer telematik-ilişkili modüllerden şu şekilde ayrışır:
  - backend-server (R155-1.1)         → bağlanılan SUNUCUYU hedefler
  - remote-telematics-exploit (R155-5.13) → TCU CİHAZININ kendisini hedefler
  - bu modül (R155-5.1)                → CİHAZ↔SUNUCU ARASINDAKİ KANALI hedefler

Üçü birlikte, telematik saldırı yüzeyinin üç farklı katmanını (sunucu,
cihaz, kanal) kapsar.

R155-5.1: Telematik kanalı istismarı (hücresel/WiFi)
"""

from ..base_plugin import BasePlugin, Finding


class TelematicsChannelPlugin(BasePlugin):
    module_id = "telematics-channel"
    name = "Telematik Kanalı İstismarı"
    surface = "telematics"
    technique = "channel-exploitation"
    r155_vector_id = "R155-5.1"
    r155_category = 5
    avcat_id = "TELEMATICS-CHANNEL"
    applicable_adapters = ["telematics", "cloud", "simulation"]
    severity_hint = "high"
    description = (
        "Hücresel/WiFi telematik kanalının bağlantı katmanına (şifreleme, "
        "kimlik doğrulama) yönelik istismar dener; sahte baz istasyonu/AP "
        "kabulü ve zayıf şifreleme senaryolarını kapsar."
    )

    def run(self, component_config: dict) -> Finding:
        comp_id = component_config.get("id", "unknown")

        try:
            exploited = self.adapter.telematics_channel_probe(comp_id)
        except NotImplementedError:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                status="inconclusive",
                title="Telematik Kanalı: Adaptör desteklemiyor",
                description=(
                    "Bu test için telematik kanalını (hücresel/WiFi) modelleyen "
                    "bir adaptör gerekli. Gerçek testte SDR/sahte baz istasyonu "
                    "gibi ekipmanlar yalnızca yetkili ortamda kullanılmalıdır."
                ),
            )
        except Exception as e:
            return self.make_error_finding(comp_id, e)

        if exploited:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                r155_category=self.r155_category,
                avcat_id=self.avcat_id,
                status="vulnerable",
                title="Telematik Kanalı: Zayıf şifreleme/kimlik doğrulama istismar edildi",
                description=(
                    f"'{comp_id}' üzerindeki hücresel/WiFi telematik kanalı, "
                    "zayıf şifreleme veya eksik karşılıklı kimlik doğrulama "
                    "nedeniyle istismar edilebildi (dinleme, enjeksiyon veya "
                    "sahte baz istasyonu/erişim noktası kabulü).\n\n"
                    "Kanal seviyesindeki bir zafiyet, backend sunucusu veya "
                    "TCU cihazı ayrı ayrı güçlendirilmiş olsa bile aradaki "
                    "iletişimi tehlikeye atabilir — konum verisi sızıntısı, "
                    "komut enjeksiyonu veya trafik manipülasyonuna yol açabilir."
                ),
                impact_safety="medium",
                impact_operational="high",
                impact_privacy="high",
                attack_feasibility="medium",
                remediation=(
                    "1. Modern, güçlü şifreleme standartları kullan (hücresel "
                    "için LTE/5G AKA, WiFi için WPA3). "
                    "2. Karşılıklı kimlik doğrulama (mutual authentication) "
                    "uygula — yalnızca istemci değil, sunucu da doğrulanmalı. "
                    "3. Sahte baz istasyonu tespiti (rogue base station "
                    "detection) mekanizmaları değerlendir. "
                    "4. Kanal üstünde de uçtan uca şifreleme (TLS) kullanarak "
                    "savunmayı katmanla."
                ),
                cvss_score=7.1,
            )

        return Finding(
            component_id=comp_id,
            test_module_id=self.module_id,
            r155_vector_id=self.r155_vector_id,
            status="not_vulnerable",
            title="Telematik Kanalı: Şifreleme/kimlik doğrulama etkili",
            description=(
                f"'{comp_id}' üzerindeki telematik kanalı istismar denemesine "
                "karşı dayanıklı; şifreleme ve kimlik doğrulama etkili görünüyor."
            ),
            attack_feasibility="low",
        )
