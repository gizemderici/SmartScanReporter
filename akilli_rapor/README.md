# Akilli Ag Tarama ve Guvenlik Analiz Sistemi

Bu proje, `Nmap` ile yapilan ag taramalarini sadece listelemek yerine yorumlayan, risk seviyelendiren, zafiyet eslestiren, saldiri senaryosu olusturan ve savunma aksiyonlari ureten web tabanli bir siber guvenlik analiz platformudur.

Proje temel olarak su sorulara cevap verir:

- Agda hangi hostlar aktif?
- Hangi portlar acik, kapali veya filtered?
- Acik servislerin risk seviyesi nedir?
- Servis surumune gore bilinen CVE kayitlari var mi?
- Bir saldirgan bu agi nasil istismar edebilir?
- Bir savunmaci bu agi nasil daha guvenli hale getirebilir?
- Ayni hedef zaman icinde nasil degisti?

Bu haliyle proje klasik bir port tarama araci olmanin otesine gecip, yarı-otomatik bir guvenlik analiz ve raporlama paneline donusmustur.

---

## Projenin Amaci

Bu sistemin amaci, ag tarama sonuclarini daha anlamli ve sunuma uygun hale getirmektir.

Standart bir tarama genelde sadece su bilgileri verir:

- hangi port acik
- hangi servis calisiyor
- hedef sistem cevap veriyor mu

Bu proje ise bunlarin uzerine ek olarak:

- risk analizi
- servis surum tespiti
- yerel ve online CVE eslestirmesi
- MITRE ATT&CK iliskilendirmesi
- saldiri senaryosu simulasyonu
- Blue Team aksiyon plani
- zaman karsilastirmasi
- grafik ve topoloji gorselleri
- HTML, TXT ve PDF ciktilari

uretir.

---

## Ana Ozellikler

### 1. Web tabanli tarama arayuzu

Kullanici hedef IP veya ag araligini web arayuzunden girer ve taramayi baslatir.

Ozellikler:

- hedef girisi
- Red Team / Blue Team modu secimi
- tarama sirasinda loading bildirimi
- dark mode / light mode gecisi
- modern dashboard arayuzu

---

### 2. Nmap tabanli tarama

Tarama motoru `scanner.py` icerisinde bulunur.

Kullanilan Nmap parametreleri:

- `-sV`: servis ve surum tespiti
- `-O`: isletim sistemi tahmini
- `-oX`: XML cikti olusturma

Bu sayede proje sadece portu degil, port arkasindaki servis ve platform baglamini da anlayabilir.

---

### 3. Akilli risk analizi

`analyzer.py` modulu XML ciktiyi okuyarak her host ve port icin yorum yapar.

Analiz edilen basliklar:

- acik port sayisi
- filtered port sayisi
- host bazli genel risk seviyesi
- port bazli risk seviyesi
- host risk skoru
- servis kategorisi
- brute-force acisindan riskli servisler
- firewall belirtisi
- OS etkisine gore risk ayarlama

Ornek:

- `445` aciksa SMB kaynakli yuksek risk
- `3389` aciksa RDP riski
- `22` aciksa SSH brute-force riski
- Windows + `445/3389` kombinasyonu daha kritik yorumlanir

---

### 4. Servis surum tespiti

Proje artik sadece servis adini degil, surum bilgisini de isler.

Ornek:

- Eskiden: `80 -> http`
- Simdi: `80 -> Apache httpd 2.4.49`

Bu gelistirme sayesinde:

- surum bazli zafiyet eslestirmesi yapilabilir
- daha gercekci saldiri senaryolari uretilir
- raporlar daha profesyonel gorunur

---

### 5. Yerel CVE eslestirme

Internet olmadan da calisabilmesi icin proje icinde yerel zafiyet eslestirme kurallari bulunur.

Ornek yerel kurallar:

- SMB -> `CVE-2017-0144` (EternalBlue)
- RDP -> `CVE-2019-0708` (BlueKeep)
- SSH -> `CVE-2018-15473`
- FTP -> `CVE-2011-2523`

Bu yapi demo ve sunum ortamlarinda oldukca stabildir cunku internet baglantisina bagimli degildir.

---

### 6. Surum-ozel CVE kurallari

Projede servis surumune ozel lokal kurallar da vardir.

Ornekler:

- Apache `2.4.49` -> `CVE-2021-41773`
- OpenSSH `7.x` -> `CVE-2018-15473`
- SMBv1 -> `CVE-2017-0144`

Bu sayede sistem, sadece servis goruldugu icin degil, kritik surum goruldugu icin de uyari verebilir.

---

### 7. NVD API ile online CVE zenginlestirmesi

Proje hibrit bir yapida calisir.

- Varsayilan mod: yerel eslestirme
- Opsiyonel mod: NVD API ile online sorgu

Bu ozellik `cve_lookup.py` modulu ile saglanir.

Avantajlari:

- daha guncel zafiyet kayitlari
- servis + surum bazli daha gercekci eslestirmeler
- internet varsa proje daha akilli hale gelir

Fallback mantigi:

- NVD API kapaliysa sadece yerel veri kullanilir
- NVD sorgusu hata verirse sistem bozulmaz
- tarama yine yerel veriyle devam eder

---

### 8. CVE eslesme nedeni gosterimi

Her CVE kaydi sadece listelenmez, neden onerildigi de yazilir.

Ornek:

- `Apache 2.4.49 goruldugu icin bu CVE onerildi.`
- `SSH servisi tespit edildigi icin bu CVE eslestirildi.`
- `NVD API uzerinde OpenSSH 7.4 aramasi yapildigi icin bulundu.`

Bu ozellik projeyi daha aciklayici ve sunum dostu hale getirir.

---

### 9. Isletim sistemi tespiti

Nmap `-O` ile elde edilen OS verisi kullanilir.

Sistem su tip tahminleri raporlayabilir:

- Windows
- Linux
- Router / ag cihazi
- Bilinmiyor

OS bilgisi sadece gosterilmez, risk analizine de etki eder.

Ornek:

- Windows + `445` daha yuksek risk
- Linux + `22` uzaktan erisim riski
- Router + yonetim portlari daha dikkat cekici

---

### 10. Firewall tespiti

Nmap ciktilarindaki `filtered` durumlari analiz edilir.

Yorum mantigi:

- `open` -> servis acik
- `closed` -> servis cevap veriyor ama kapali
- `filtered` -> muhtemel firewall / ACL etkisi

Raporda:

- toplam filtered port sayisi
- firewall belirtisi olan host sayisi
- host bazli firewall yorumu

gosterilir.

---

### 11. Brute-force risk analizi

Asagidaki servisler brute-force acisindan dikkatle izlenir:

- `21` FTP
- `22` SSH
- `3389` RDP

Bu servisler aciksa sistem:

- port detayinda brute-force notu yazar
- host bazli riskli servis sayisini hesaplar
- genel ozet ekranina yansitir

---

### 12. Saldiri senaryosu simulasyonu

`scenario_generator.py` modulu, bulunan servisleri olasi saldiri akislarina donusturur.

Ornek senaryolar:

- SMB istismar senaryosu
- web sunucusu istismar senaryosu
- kimlik bilgisi zorlama senaryosu
- sinirli kesif senaryosu

Her senaryo icin:

- adim adim akış
- sonuc
- etki
- siddet seviyesi
- etki skoru

bilgileri uretir.

Bu ozellik sayesinde sistem sadece “risk var” demez, “bu risk nasil istismar edilir?” sorusuna da cevap verir.

---

### 13. MITRE ATT&CK eslestirmesi

Saldiri senaryolari MITRE ATT&CK taktik ve teknikleriyle iliskilendirilir.

Ornek eslestirmeler:

- SMB istismari -> `T1021.002`, `T1203`
- web istismari -> `T1190`, `T1005`
- brute-force -> `T1110`, `T1078`
- ag kesfi -> `T1046`, `T1595`

Arayuz ve raporlar su bilgileri gosterir:

- toplam MITRE teknik sayisi
- genel MITRE ozeti
- senaryo bazinda tactic / technique / technique ID

Bu katman projeye daha profesyonel bir siber guvenlik cercevesi kazandirir.

---

### 14. Red Team / Blue Team modu

Projede iki farkli analiz modu bulunur.

#### Red Team modu

Soru:

- Bu ag nasil hacklenir?

Odak:

- exploit senaryolari
- saldiri akis mantigi
- MITRE ATT&CK teknikleri
- saldirgan bakis acisi

#### Blue Team modu

Soru:

- Bu ag nasil korunur?

Odak:

- savunma onerileri
- firewall yorumlari
- yamalama gereksinimleri
- servis kapatma / kisitlama
- aksiyon plani

---

### 15. Onceliklendirilmis aksiyon plani

Blue Team modunda sistem sadece genel tavsiye vermez.

Ayrica su turde sirali aksiyonlar uretir:

- once bunu yamala
- sonra bu servisi kisitla
- sonra brute-force korumasi ekle
- sonra segmentasyon uygula

Puanlanan alanlar:

- kritik CVE
- yuksek riskli portlar
- brute-force acik servisler
- SMB / NetBIOS gibi lateral movement yuzeyleri
- firewall eksigi

Boylece rapor teknik oldugu kadar operasyonel de hale gelir.

---

### 16. Zaman karsilastirma ozelligi

Proje ayni hedefin onceki tarama sonucunu saklar ve yeni taramayla karsilastirir.

`history_tracker.py` modulu sayesinde:

- yeni acilan portlar
- kapanan portlar
- risk skoru degisimleri
- risk artisi olan hostlar

hesaplanir.

Bu ozellik, projeyi tek seferlik analiz araci olmaktan cikarip surec izleme aracina yaklastirir.

---

### 17. Grafikler ve ag topolojisi

`chart_generator.py` modulu ile otomatik gorseller uretilir.

Uretilen grafikler:

- host risk dagilimi
- isletim sistemi dagilimi
- ag topolojisi

Ag topolojisinde:

- tarayan sistem
- hedef ag
- bulunan hostlar

gorsellestirilir.

Risk seviyesi host dugum renklerine de yansitilir:

- kirmizi -> yuksek risk
- turuncu -> orta risk
- yesil -> dusuk risk
- gri -> bilinmiyor

`networkx` kuruluysa daha gelismis topoloji cizimi kullanilir, degilse `matplotlib` fallback devreye girer.

---

### 18. Modern web arayuzu

Arayuz `templates/index.html` icinde gelistirilmistir.

Mevcut tasarim ozellikleri:

- modern dashboard hissi
- hero alan
- KPI kartlari
- gorsel paneller
- host bazli kart yapisi
- dark mode / light mode
- PDF / HTML arac cubugu
- Red Team / Blue Team odakli yerlesim

Bu tasarim, projeyi teknik ama ayni zamanda sunuma uygun hale getirir.

---

### 19. Raporlama sistemi

`reporter.py` modulu birden fazla cikti uretir:

- TXT rapor
- HTML rapor
- PDF rapor

PDF akisi hibrit calisir:

- `reportlab` varsa gercek PDF dosyasi olusturulur
- yoksa yazdirilabilir HTML fallback kullanilir

Boylece proje bagimlilik durumuna gore esnek davranir.

---

## Proje Mimarisi

Proje daha profesyonel gorunmesi ve bakimi kolay olmasi icin modullere ayrilmistir.

### Dosya yapisi

```text
akilli_rapor/
├── analyzer.py
├── chart_generator.py
├── cve_lookup.py
├── env_loader.py
├── history_tracker.py
├── main.py
├── reporter.py
├── scanner.py
├── scenario_generator.py
├── team_advisor.py
├── web_app.py
├── .env.example
├── history/
├── reports/
├── scan_results/
├── static/
└── templates/
    └── index.html
```

### Moduller

- `scanner.py`
  - Nmap komutunu calistirir.
- `analyzer.py`
  - XML sonucunu okuyup risk, CVE, OS, firewall ve brute-force analizini yapar.
- `cve_lookup.py`
  - NVD API ile online CVE zenginlestirmesi yapar.
- `scenario_generator.py`
  - saldiri senaryolarini ve MITRE ATT&CK baglantilarini uretir.
- `team_advisor.py`
  - Red Team ozeti, Blue Team onerileri ve oncelik planini olusturur.
- `history_tracker.py`
  - zaman karsilastirmasi ve snapshot kaydi tutar.
- `chart_generator.py`
  - risk, OS ve topoloji gorsellerini olusturur.
- `reporter.py`
  - TXT, HTML ve PDF raporlar uretir.
- `web_app.py`
  - Flask tabanli web arayuzunu yonetir.
- `main.py`
  - terminalden calisan CLI surumudur.
- `env_loader.py`
  - `.env` benzeri ayarlari yukler.

---

## Kullanilan Teknolojiler

- Python
- Flask
- Nmap
- XML parsing
- Matplotlib
- NetworkX (opsiyonel)
- ReportLab (opsiyonel)
- NVD API (opsiyonel)
- HTML / CSS / Jinja2

---

## Kurulum

### Gereksinimler

Sistemde su bilesenlerin bulunmasi gerekir:

- Python 3
- Nmap

Python paketleri:

- `flask`
- `matplotlib`
- `networkx` (opsiyonel ama tavsiye edilir)
- `reportlab` (opsiyonel, gercek PDF icin)

### Ornek kurulum

```powershell
cd c:\project\akilli_rapor
pip install flask matplotlib networkx reportlab
```

Not:

- `networkx` kurulu degilse topoloji fallback ile yine uretilir.
- `reportlab` kurulu degilse PDF tarafinda yazdirilabilir HTML fallback kullanilir.

---

## Ortam Degiskenleri

Projede `.env.example` dosyasi bulunur.

Ornek:

```env
# NVD online mode
NVD_API_ENABLED=true

# Optional NVD API key
NVD_API_KEY=

# Optional tuning
NVD_RESULTS_PER_PAGE=3
NVD_API_TIMEOUT=8
```

### Aciklama

- `NVD_API_ENABLED`
  - `true` ise online NVD sorgusu aktif olur.
- `NVD_API_KEY`
  - NVD API anahtari.
- `NVD_RESULTS_PER_PAGE`
  - sorgu basina alinacak sonuc sayisi.
- `NVD_API_TIMEOUT`
  - API timeout suresi.

---

## Calistirma

### Web arayuzu

```powershell
cd c:\project\akilli_rapor
python web_app.py
```

Ardindan tarayicida:

```text
http://127.0.0.1:5000
```

### Terminal surumu

```powershell
cd c:\project\akilli_rapor
python main.py
```

CLI modunda kullanici:

- hedef IP veya ag araligini girer
- Red Team veya Blue Team modunu secer
- sonuc raporlarini alir

---

## Web Arayuzunde Neler Var

Ana sayfada su alanlar bulunur:

- modern hero panel
- tarama formu
- Red Team / Blue Team secimi
- HTML ve PDF rapor butonlari
- dark mode / light mode
- KPI kartlari
- genel ag ozeti
- risk dagilimi grafigi
- OS dagilimi
- ag topolojisi
- zaman karsilastirmasi
- host kartlari
- saldiri senaryolari
- savunma onerileri
- MITRE ATT&CK eslesmeleri
- acik port ve CVE detay tablosu

---

## Raporlar

Tarama tamamlandiginda proje `reports/` klasoru altinda cikti uretir.

### 1. TXT rapor

Metin tabanli klasik rapor.

Icerik:

- genel ozet
- host listesi
- port detaylari
- CVE bilgileri
- Red Team veya Blue Team yorumu

### 2. HTML rapor

Tarayici uzerinden gorulebilen detayli rapor.

### 3. PDF rapor

- `reportlab` varsa dogrudan PDF dosyasi
- yoksa yazdirilabilir HTML akisi

---

## Verilerin Kaydedildigi Klasorler

- `scan_results/`
  - Nmap XML ciktilari
- `static/`
  - risk, OS ve topoloji gorselleri
- `reports/`
  - TXT / HTML / PDF raporlar
- `history/`
  - onceki tarama snapshot kayitlari

---

## Ornek Analiz Akisi

Bir tarama su sirayla ilerler:

1. Kullanici hedefi girer.
2. `scanner.py` Nmap taramasini baslatir.
3. XML sonuc `analyzer.py` tarafindan okunur.
4. Servis, surum, OS, risk ve firewall analizi yapilir.
5. Yerel CVE eslestirmesi uygulanir.
6. Gerekirse NVD API ile online zenginlestirme yapilir.
7. `scenario_generator.py` saldiri senaryolari ve MITRE eslesmeleri uretir.
8. `team_advisor.py` Red Team ozeti veya Blue Team aksiyon plani olusturur.
9. `history_tracker.py` onceki taramayla farklari hesaplar.
10. `chart_generator.py` grafik ve topoloji dosyalarini olusturur.
11. `reporter.py` TXT / HTML / PDF raporlar uretir.
12. Sonuclar web panelinde gosterilir.

---

## Projede Uygulanan Gelistirmelerin Ozeti

Bu projede asagidaki gelistirmeler uygulanmistir:

- HTML raporu ac butonu
- PDF raporu ac butonu
- loading mesaji
- risk badge sistemi
- grafik uretimi
- grafiklerin arayuze eklenmesi
- moduler klasor yapisi
- yerel CVE entegrasyonu
- online NVD API entegrasyonu
- `.env` destegi
- servis surum tespiti
- surum-ozel CVE kurallari
- eslesme nedeni gosterimi
- zaman karsilastirma sistemi
- risk degisimi rozetleri
- PDF export
- dark mode
- network topology gorseli
- topolojide risk bazli renkler
- OS tespiti
- OS dagilim grafigi
- firewall tespiti
- brute-force risk analizi
- saldiri senaryosu simulasyonu
- senaryo siddeti ve etki skoru
- Red Team / Blue Team modu
- onceliklendirilmis aksiyon plani
- MITRE ATT&CK eslestirmesi
- modern dashboard arayuzu

---

## Projenin Guclu Yonleri

- Sadece port taramasi yapmaz, yorumlar.
- Sunuma uygun modern arayuze sahiptir.
- Internet olmadan da yerel kurallarla calisabilir.
- Internet varsa online CVE zenginlestirmesi sunar.
- Red Team ve Blue Team yaklasimini birlikte sunar.
- MITRE ATT&CK gibi profesyonel bir guvenlik cercevesi kullanir.
- Zaman icindeki degisimleri izleyebilir.
- Gorsel, rapor ve analiz katmanlari birlikte calisir.

---

## Gelistirilebilecek Alanlar

Ileride eklenebilecek basliklar:

- CVSS puanlama
- asset kritikligi
- kullanici giris sistemi
- coklu dil destegi
- JSON export
- e-posta raporlama
- tarihsel trend grafigi
- daha gelismis dashboard filtreleri
- rol bazli gorunum
- canli bildirim mekanizmasi

---

## Sonuc

Bu proje, klasik bir ag tarama ciktisini alip onu:

- teknik olarak zengin,
- gorsel olarak guclu,
- raporlama acisindan profesyonel,
- hem saldirgan hem savunmaci bakis acisina sahip

bir guvenlik analiz sistemine donusturmektedir.

Ozellikle egitim, demo, bitirme projesi ve sunum ortamlari icin etkileyici bir yapidadir.
