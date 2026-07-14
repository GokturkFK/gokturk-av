"""
GÖKTÜRK — Arka Uç / Filo Yönetim Sunucusu Güvenlik Modülü (R155 Kategori 1)
Taktik: aracın bağlandığı backend (filo yönetim/telematik) sunucusuna beş
senaryo uygular:

  - weak_auth                       → R155-1.1 (yetkisiz uzaktan sunucu erişimi)
  - insider_privilege_abuse         → R155-1.2 (personel tarafından hak kötüye kullanımı)
  - unrestricted_internet_exposure  → R155-1.3 (sunucuya yetkisiz internet erişimi)
  - supply_chain_compromise         → R155-1.4 (tedarik zinciri saldırısı — backend)
  - dos                             → R155-1.5 (araç servisleri arka uç sunucusuna DoS)

Saha araştırmasında vurgulandığı gibi backend, filo homojenliği nedeniyle
özellikle kritik bir yüzeydir: tek bir backend zaafı TÜM FİLOYU aynı anda
etkileyebilir.

Dört farklı katman test edilir: weak_auth kimlik doğrulamanın GÜCÜNÜ,
insider_privilege_abuse ZATEN geçerli bir oturumun yetki/en-az-yetki
sınırını, unrestricted_internet_exposure arayüzün BAŞTAN İTİBAREN
internetten erişilebilir olup olmaması gereken ağ çevre güvenliğini
(perimeter), supply_chain_compromise ise sunucunun GÜVENDİĞİ tedarik
zincirini hedefler — dördü de farklı bir savunma katmanının kendi
başına yeterli olmadığını gösterir.

Her zafiyetli senaryo, KENDİ R155 vektörüyle AYRI bir Finding olarak
raporlanır (List[Finding]) — böylece beş vektör de kapsam sayımına
doğru şekilde yansır.
"""

from ..base_plugin import BasePlugin, Finding

_SCENARIOS = {
    "weak_auth": {
        "vector": "R155-1.1",
        "label": "Yetkisiz uzaktan sunucu erişimi",
        "impact_safety": "high",
        "impact_privacy": "high",
        "cvss": 8.6,
        "remediation": (
            "1. Çok faktörlü kimlik doğrulama (MFA) ve güçlü parola politikası "
            "zorunlu kıl; varsayılan kimlik bilgilerini asla üretimde bırakma. "
            "2. En az yetki (least privilege) ilkesiyle personel erişimini sınırla."
        ),
    },
    "dos": {
        "vector": "R155-1.5",
        "label": "Araç servisleri arka uç sunucusuna DoS",
        "impact_safety": "medium",
        "impact_privacy": "none",
        "cvss": 6.5,
        "remediation": (
            "1. API/yönetim paneli için hız sınırlama (rate limiting) ve anomali "
            "tespiti uygula. "
            "2. Backend'i DDoS koruması olan bir CDN/WAF arkasına al."
        ),
    },
    "supply_chain_compromise": {
        "vector": "R155-1.4",
        "label": "Tedarik zinciri saldırısı (backend)",
        "impact_safety": "high",
        "impact_privacy": "high",
        "cvss": 8.1,
        "remediation": (
            "1. CI/CD hattına giren tüm üçüncü taraf paket/kütüphane/konteyner "
            "imajlarında imza doğrulaması ve SBOM (yazılım malzeme listesi) "
            "eşleşmesi zorunlu kıl. "
            "2. Bağımlılık kaynaklarını (package registry) izin listesine "
            "(allow-list) al; imzasız/doğrulanmamış kaynaklardan çekmeyi engelle."
        ),
    },
    "insider_privilege_abuse": {
        "vector": "R155-1.2",
        "label": "Personel tarafından hak kötüye kullanımı",
        "impact_safety": "medium",
        "impact_privacy": "high",
        "cvss": 6.8,
        "remediation": (
            "1. En az yetki (least privilege) ilkesini rol tabanlı erişim "
            "kontrolü (RBAC) ile teknik olarak zorunlu kıl; yetki genişletmeyi "
            "yalnızca onay süreciyle mümkün kıl. "
            "2. Kapsam dışı/hassas işlemleri (toplu veri dışa aktarma, başka "
            "operatörün filosuna erişim) değişmez denetim kaydına (immutable "
            "audit log) yaz ve anomali tespitiyle işaretle."
        ),
    },
    "unrestricted_internet_exposure": {
        "vector": "R155-1.3",
        "label": "Sunucuya yetkisiz internet erişimi",
        "impact_safety": "high",
        "impact_privacy": "medium",
        "cvss": 7.5,
        "remediation": (
            "1. Yönetim paneli/iç API'leri genel internetten tamamen kaldır; "
            "yalnızca VPN veya kurumsal ağ üzerinden erişilebilir yap. "
            "2. Ağ segmentasyonu ve IP izin listesi (allow-list) ile dış "
            "dünyaya açık yüzeyi asgariye indir; düzenli dış yüzey taraması "
            "(attack surface scanning) yap."
        ),
    },
}

_COMMON_REMEDIATION = (
    " 3. Düzenli sızma testi ve üçüncü taraf bileşen denetimi programını "
    "sürekli hale getir."
)


class BackendServerPlugin(BasePlugin):
    module_id = "backend-server"
    name = "Arka Uç Sunucu Güvenliği"
    surface = "backend"
    technique = "server-access"
    r155_vector_id = "R155-1.1"   # birincil (koruma aktifse tek özet Finding için)
    r155_category = 1
    avcat_id = "BACKEND-SERVER-ACCESS"
    applicable_adapters = ["telematics", "cloud", "simulation"]
    severity_hint = "high"
    description = (
        "Araç filo yönetim/telematik backend sunucusuna zayıf kimlik "
        "doğrulama (R155-1.1), personel hak kötüye kullanımı (R155-1.2), "
        "yetkisiz internet erişimi (R155-1.3), tedarik zinciri saldırısı "
        "(R155-1.4) ve servis engelleme (R155-1.5) senaryolarıyla erişim/"
        "dayanıklılık testi yapar."
    )

    def run(self, component_config: dict):
        comp_id = component_config.get("id", "unknown")

        try:
            outcomes = {
                scenario: self.adapter.backend_server_probe(comp_id, scenario)
                for scenario in _SCENARIOS
            }
        except NotImplementedError:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                status="inconclusive",
                title="Backend Sunucu: Adaptör desteklemiyor",
                description=(
                    "Bu test için backend/filo yönetim API'sini modelleyen bir "
                    "adaptör gerekli. Gerçek backend testi yalnızca yetkili "
                    "ortamda ve sahibinin izniyle yapılır."
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
                title="Backend Sunucu: Erişim/dayanıklılık korumaları aktif",
                description=(
                    "Beş backend saldırı senaryosunun tamamı ilgili koruma "
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
                title=f"Backend Sunucu: {meta['label']} başarılı",
                description=(
                    f"'{comp_id}' üzerinden erişilen backend sunucusunda "
                    f"'{meta['label'].lower()}' senaryosu başarılı oldu: "
                    f"{outcome.get('detail', '')}\n\n"
                    "Filo homojenliği nedeniyle backend zaafları özellikle "
                    "kritiktir: tek bir sunucu güvenlik açığı, o backend'e "
                    "bağlı TÜM araçları aynı anda etkileyebilir."
                ),
                impact_safety=meta["impact_safety"],
                impact_operational="high",
                impact_financial="medium",
                impact_privacy=meta["impact_privacy"],
                attack_feasibility="medium",
                remediation=meta["remediation"] + _COMMON_REMEDIATION,
                cvss_score=meta["cvss"],
            ))
        return findings
