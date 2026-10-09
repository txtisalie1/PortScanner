# PortScanner

**PortScanner**, Windows üzerindeki etkin TCP/UDP bağlantılarını süreçlerle eşleştiren,
açıklanabilir risk kuralları uygulayan ve sonuçları JSON olarak dışa aktarabilen açık
kaynaklı bir Python CLI aracıdır.

> Projenin adına rağmen bu sürüm uzak sistemlere port taraması yapmaz. Yalnızca çalıştığı
> bilgisayarın mevcut ağ bağlantılarını inceler.

## Özellikler

- Etkin TCP/UDP bağlantıları, yerel ve uzak adresler
- PID, süreç adı, çalıştırılabilir dosya yolu ve SHA-256 özeti
- Bilinmeyen süreçler ve hassas/yaygın olmayan uzak portlar için açıklanabilir uyarılar
- JSON güvenlik raporu
- Daha önce görülmeyen süreç/adres/port birleşimlerini gösteren baseline karşılaştırması
- Periyodik canlı izleme
- Erişim reddi ve tarama sırasında sonlanan süreçler için güvenli hata yönetimi

PortScanner'ın bulguları inceleme önceliği sağlar; tek başına zararlı yazılım teşhisi koymaz.

## Gereksinimler

- Windows 10/11
- Python 3.11 veya üzeri

Bazı süreç ve bağlantı ayrıntıları Windows'ta yalnızca yönetici yetkisiyle görülebilir.

## Kurulum

Depoyu klonlayıp sanal ortam oluşturun:

```powershell
git clone https://github.com/your-username/PortScanner.git
cd PortScanner
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e .
```

Geliştirme araçlarıyla kurulum:

```powershell
python -m pip install -e ".[dev]"
```

## Kullanım

### Tek seferlik tarama

```powershell
portscanner scan
```

UDP dahil tüm internet soketlerini görmek için:

```powershell
portscanner scan --protocol all --listening
```

SHA-256 hesaplamadan ilk 25 satırı gösterip JSON raporu yazmak için:

```powershell
portscanner scan --no-hash --limit 25 --json report.json
```

Paket kurulmadan da çalıştırılabilir:

```powershell
python -m portscanner scan
```

### Baseline oluşturma ve karşılaştırma

Bilgisayarın normal kullanım durumundayken bir baseline oluşturun:

```powershell
portscanner baseline --output portscanner-baseline.json
```

Sonraki taramayı bu kayıtla karşılaştırın:

```powershell
portscanner scan --baseline portscanner-baseline.json
```

Yeni bir bağlantı tek başına tehlike anlamına gelmez. Uygulama güncellemeleri, CDN'ler ve
değişken bulut adresleri doğal olarak yeni kayıtlar üretebilir.

### Canlı izleme

```powershell
portscanner monitor --interval 3 --limit 30
```

İzlemeyi `Ctrl+C` ile durdurabilirsiniz.

## Komut özeti

```text
portscanner scan [--protocol tcp|udp|all] [--listening] [--no-hash]
                 [--limit N] [--json FILE] [--baseline FILE]
portscanner baseline [--protocol tcp|udp|all] [--output FILE]
portscanner monitor [--interval SECONDS] [--baseline FILE]
```

Tüm seçenekler için:

```powershell
portscanner --help
portscanner scan --help
```

## Risk kuralları

| Kural | Seviye | Açıklama |
|---|---:|---|
| `unknown-process` | Orta | Bağlantı sahibi süreç tanımlanamadı |
| `public-sensitive-service` | Yüksek | Genel internette hassas servis portuna bağlantı var |
| `uncommon-remote-port` | Düşük | Genel internette yaygın olmayan uzak port kullanılıyor |
| `new-baseline-entry` | Bilgi | Süreç/adres/port birleşimi baseline içinde yok |

Kurallar özellikle açıklanabilir ve muhafazakâr tutulmuştur. Bir bulguyu süreç yolu, dosya
özeti, uygulamanın beklenen davranışı ve kurum politikalarıyla birlikte değerlendirin.

## JSON raporu

Rapor; tarama zamanı, sistem bilgisi, bağlantılar, süreç ayrıntıları, bulgular ve tarama
hatalarını içerir. Özetler rapora yazılır fakat hiçbir dosya üçüncü bir hizmete yüklenmez.

## Proje yapısı

```text
PortScanner/
├── portscanner/
│   ├── cli.py          # Komut satırı arayüzü
│   ├── scanner.py      # Ağ bağlantılarını toplar
│   ├── process_info.py # Süreç yolu ve SHA-256 bilgisi
│   ├── analyzer.py     # Açıklanabilir risk kuralları
│   ├── reporter.py     # JSON raporu ve baseline
│   └── models.py       # Veri modelleri
├── tests/
├── pyproject.toml
└── LICENSE
```

## Testler

```powershell
pytest
ruff check .
```

## Gizlilik ve güvenlik

- Ağ verileri ve süreç bilgileri yerel olarak işlenir.
- JSON raporlarında kullanıcı adı, dosya yolu ve uzak IP gibi hassas olabilecek bilgiler
  bulunabilir. Raporu paylaşmadan önce inceleyin.
- Aracı yalnızca sahibi olduğunuz veya inceleme izniniz bulunan sistemlerde kullanın.

## Lisans

[MIT](LICENSE)

