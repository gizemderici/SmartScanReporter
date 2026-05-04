# Akilli Ag Tarama ve Guvenlik Analiz Sistemi - Guncel Proje Raporu

## Giris

Bu proje, klasik `nmap` ciktilarini daha anlamli hale getirmek icin gelistirilmis web tabanli bir ag tarama, analiz ve raporlama platformudur.

Sistem sadece "hangi port acik?" sorusuna cevap vermez. Bunun yerine:

- risk seviyesi
- servis kategorisi
- bilinen yerel CVE eslesmeleri
- online NVD zenginlestirmesi
- saldiri senaryolari
- savunma onerileri
- gecmis karsilastirmasi
- grafik ve topoloji gorselleri

gibi ek katmanlar sunar.

Bu rapor, projenin su anki gercek kod durumuna gore hazirlanmistir.

---

## Projenin Amaci

Projenin temel amaci, ag tarama verilerini:

- daha okunur
- daha yorumlanabilir
- daha sunum dostu
- daha operasyonel

hale getirmektir.

Standart bir tarama genellikle sadece:

- acik portlari
- servis adlarini
- hedefin cevap verip vermedigini

gosterir.

Bu proje ise bunun ustune:

- host risk skoru
- servis bazli yorum
- CVE eslestirme
- Red Team / Blue Team bakisi
- grafikler
- discovery gecmisi
- rapor ciktilari

ekler.

---

## Ana Yetenekler

### 1. Web Tabanli Arayuz

Proje Flask tabanli bir web arayuzu sunar.

Mevcut arayuz ozellikleri:

- hedef IP veya ag araligi girisi
- tarama turu secimi
- Red Team / Blue Team modu
- dark / light mode
- export merkezi
- canli filtreleme ve arama
- host bazli kart gorunumu

Ana dosyalar:

- `web_app.py`
- `templates/index.html`

### 2. Tarama Turu Secme Sistemi

Kullanici sabit bir tarama tipine bagli degildir. Arayuzde secilebilir profiller vardir:

- `Hizli Tarama`
  - `nmap hedef`
- `SYN Tarama`
  - `nmap -sS hedef`
- `Detayli Tarama`
  - `nmap -sV -O hedef`
- `UDP Tarama`
  - `nmap -sU hedef`
- `Ping Scan`
  - `nmap -sn hedef`
- `Zafiyet Taramasi`
  - `nmap -sV --script vuln hedef`

Bu mantik `scanner.py` icinde komut profilleri olarak tanimlanmistir.

### 3. Canli Tarama Ilerlemesi

Tarama arka planda calisir ve arayuzde durum bilgisi gosterilir.

Gosterilen bilgiler:

- yuzde bazli ilerleme
- asama listesi
- su anki adim
- tahmini kalan sure
- son olaylar logu
- iptal et / yeniden dene

Izlenen adimlar:

- Nmap taramasi
- XML cozumleme
- CVE zenginlestirme
- senaryo uretimi
- takim modu analizi
- gecmis karsilastirma
- grafik / topoloji
- rapor olusturma

### 4. Network Discovery Ekrani

Projede ayri bir `Network Discovery` sayfasi vardir.

Bu ekran subnet girerek:

- agdaki aktif cihazlari bulur
- cihaz sayisini gosterir
- IP / hostname / MAC / vendor bilgisini listeler
- discovery topolojisi cizer

Kullanilan komut:

- `nmap -sn 192.168.1.0/24`

Ek olarak ayni subnet tekrar tarandiginda:

- yeni cihazlar
- artik gorunmeyen cihazlar
- onceki discovery zamani

karsilastirilir.

Yeni bulunan cihazlar `Yeni Cihaz` rozeti ile isaretlenir.

### 5. Akilli Risk Analizi

`analyzer.py`, Nmap XML sonucunu okuyarak host ve port bazli yorum yapar.

Analiz edilen alanlar:

- toplam acik port
- filtered port sayisi
- host risk seviyesi
- host skorlamasi
- port risk seviyesi
- servis kategorisi
- brute-force notlari
- firewall belirtisi
- OS etkisine gore risk artirma

Risk mantigi port kurallarina dayanir.

Ornekler:

- `445` -> SMB riski
- `3389` -> RDP riski
- `22` -> SSH brute-force riski
- `53/udp` -> DNS servisi
- `69/udp` -> TFTP servisi
- `123/udp` -> NTP servisi
- `161/udp` -> SNMP servisi

### 6. UDP Servis Yorumu

UDP tarama secildiginde sistem sadece ham port gostermez.

Ozellikle su servisler icin yorum uretilir:

- `53/udp` DNS
- `69/udp` TFTP
- `123/udp` NTP
- `161/udp` SNMP

Bu servisler icin:

- kategori
- risk seviyesi
- yerel CVE
- guvenlik onerisi

sunulur.

Ek olarak:

- ana panelde `UDP Servisleri` ozeti
- TXT raporda `UDP SERVIS OZETI`
- HTML raporda `UDP Servis Ozeti`

bolumu bulunur.

### 7. Yerel ve Online CVE Eslesmesi

Sistem iki farkli CVE katmani kullanir:

- yerel servis kurallari
- opsiyonel NVD API zenginlestirmesi

Yerel kural ornekleri:

- FTP -> `CVE-2011-2523`
- SSH -> `CVE-2018-15473`
- SMB -> `CVE-2017-0144`
- RDP -> `CVE-2019-0708`
- DNS -> `CVE-2020-8616`
- TFTP -> `CVE-2019-1350`
- NTP -> `CVE-2015-7704`
- SNMP -> `CVE-2014-2284`

Version bazli kurallar da vardir:

- Apache `2.4.49`
- OpenSSH `7.x`
- SMBv1

### 8. Saldiri Senaryolari

`scenario_generator.py` acik servisleri olasi saldiri akislarina donusturur.

Mevcut senaryolar:

- SMB istismar senaryosu
- web sunucusu istismar senaryosu
- kimlik bilgisi zorlama senaryosu
- sinirli kesif senaryosu

Her senaryoda:

- adimlar
- sonuc
- etki
- siddet
- etki skoru

yer alir.

### 9. MITRE ATT&CK Eslestirmesi

Senaryolar MITRE ATT&CK taktik ve teknikleri ile baglanir.

Ornek teknikler:

- `T1021.002`
- `T1203`
- `T1190`
- `T1110`
- `T1046`

Bu bilgi hem arayuzde hem raporlarda gosterilir.

### 10. Red Team / Blue Team Analizi

Sistem iki farkli yorum modu sunar.

Red Team:

- saldiri akislarini one cikarir
- en olasi istismar yolunu ozetler

Blue Team:

- savunma onerileri
- sirali aksiyonlar
- oncelik puani

olusturur.

### 11. Gecmis Karsilastirmasi

Tarama sonuclari `history/` altinda saklanir.

Sistem su farklari hesaplar:

- yeni acilan portlar
- kapanan portlar
- risk artisi
- host skor degisimi

Bu ozellik hedef bazli surec takibi saglar.

### 12. Grafik ve Topoloji Uretimi

`chart_generator.py` su gorselleri olusturur:

- risk dagilimi
- isletim sistemi dagilimi
- ag topolojisi
- discovery topolojisi

`networkx` varsa gelismis topoloji cizimi kullanilir. Yoksa `matplotlib` fallback ile devam edilir.

### 13. Raporlama

`reporter.py` uc farkli cikti üretir:

- TXT
- HTML
- PDF

PDF akis mantigi:

- `reportlab` varsa gercek PDF
- yoksa yazdirilabilir HTML

Raporlarda bulunan alanlar:

- genel ag ozeti
- host listesi
- port detaylari
- CVE bilgileri
- Red Team / Blue Team yorumu
- zaman karsilastirmasi
- UDP servis ozeti

---

## Teknik Mimari

### Ana Dosyalar

- `scanner.py`
  - tarama profilleri ve Nmap komutlarini yonetir
- `analyzer.py`
  - XML sonucunu yorumlar
- `cve_lookup.py`
  - NVD API zenginlestirmesi yapar
- `scenario_generator.py`
  - saldiri senaryolari uretir
- `team_advisor.py`
  - Red Team / Blue Team analizini olusturur
- `history_tracker.py`
  - hedef ve discovery snapshot karsilastirmasi yapar
- `chart_generator.py`
  - grafik ve topoloji cizer
- `reporter.py`
  - TXT / HTML / PDF rapor uretir
- `web_app.py`
  - Flask route ve ekran mantigini yonetir

### Dizinler

- `templates/`
  - `index.html`
  - `discovery.html`
- `static/`
  - grafikler ve topoloji gorselleri
- `reports/`
  - uretile rapor dosyalari
- `scan_results/`
  - XML ciktilari
- `history/`
  - onceki scan ve discovery snapshotlari

---

## Kullanim Senaryolari

### Senaryo 1: Hedefte detayli guvenlik analizi

1. Kullanici hedef IP girer.
2. `Detayli Tarama` secer.
3. Sonuclarda risk, CVE, senaryo ve rapor ciktisi alir.

### Senaryo 2: Sadece agda kimler var?

1. Kullanici `Network Discovery` ekranina gider.
2. Subnet girer.
3. Aktif cihaz listesini gorur.
4. Tekrar tarama yaparak yeni cihazlari tespit eder.

### Senaryo 3: UDP servislerini ayiklama

1. Kullanici `UDP Tarama` secer.
2. Tarama tamamlanir.
3. DNS, NTP, SNMP, TFTP gibi servisler ust seviyede ozetlenir.

---

## Sinirlar ve Notlar

Bu rapor bilincli olarak su anda kodda gercekten bulunan ozelliklere gore hazirlanmistir.

Bu nedenle:

- gelismis canli progress var
- discovery ekrani var
- tarama turu secimi var
- UDP tarama ve UDP ozeti var

Ancak su alanlar halen gelistirilebilir:

- daha ileri CVSS puanlama
- daha gelismis trend grafikleri
- kullanici yonetimi
- JSON export
- bildirim mekanizmasi

---

## Sonuc

Bu proje, klasik bir Nmap taramasini alip onu:

- yorumlayan
- siniflandiran
- raporlayan
- gorsellestiren
- karsilastiran

bir sisteme donusturmektedir.

Ozellikle:

- bitirme projesi
- demo ortami
- egitim
- sunum
- temel guvenlik analizleri

icin oldukca guclu bir taban sunar.
