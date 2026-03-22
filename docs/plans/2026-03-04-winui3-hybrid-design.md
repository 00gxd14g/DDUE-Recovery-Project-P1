# PyDDEU WinUI 3 Hybrid Design

**Date:** 2026-03-04  
**Status:** Approved (Approach 2)

## Goal

Mevcut Python adli kurtarma motorunu koruyarak, tamamen WinUI 3 (C#) tabanlı gelişmiş bir Windows masaüstü arayüzü üretmek ve uygulamanın çalıştığını doğrulamak.

## Context

- Mevcut proje `pyddeu/` altında Python recovery motoruna sahip.
- Eski GUI `tkinter` ile `pyddeu/gui.py` içinde.
- Kullanıcı beklentisi: arayüzün tamamı WinUI 3 olması ve uygulamanın çalışması.

## Chosen Approach

**Hibrit mimari (WinUI 3 + Python Bridge):**

- UI katmanı: C# / WinUI 3 desktop shell
- Recovery katmanı: mevcut Python modülleri (`pyddeu.*`)
- Köprü katmanı: `pyddeu/winui_bridge.py` (JSON command protocol, stdout event stream)

Bu yaklaşım, çalışan recovery algoritmalarını yeniden yazmadan modern native UI teslimini sağlar.

## Alternatives Considered

1. Tam C# yeniden yazım
- Artı: tek dil/tek runtime
- Eksi: yüksek risk ve uzun süre, recovery davranış regresyon riski

2. WinUI 3 + Python bridge (**seçilen**)
- Artı: hızlı teslim, düşük algoritma riski, mevcut doğrulanmış kod tekrar kullanımı
- Eksi: process orchestration ve protocol yönetimi gerekir

3. WinUI 3 + Python HTTP servis
- Artı: servisleşme ve dağıtık kullanım kolay
- Eksi: port/süreç/servis yönetimi daha karmaşık

## High-Level Architecture

1. `winui/PyDDEU.WinUI` (C# WinUI app)
- Shell window, command bar, partition list, file tree, progress/status, log panel
- Async command dispatcher
- Process host for Python bridge
- ViewModels + DTO contracts

2. `pyddeu/winui_bridge.py`
- İstek/yanıt tabanlı komutlar:
  - `list_disks`
  - `connect`
  - `scan_partitions`
  - `deep_ntfs_scan`
  - `mft_scan`
  - `file_carve`
  - `create_image`
  - `recover_selected`
  - `recover_folder`
  - `stop`
- Log/progress/event satırları JSON olarak stdout’a yazar

3. Existing Python Core (unchanged business logic)
- `pyddeu.io`, `pyddeu.partitions`, `pyddeu.mft`, `pyddeu.recover`, `pyddeu.imager`, `pyddeu.carve`

## Data Flow

1. WinUI kullanıcı aksiyonu üretir (ör. `Scan Partitions`).
2. C# process host, Python bridge’e JSON komut gönderir.
3. Bridge uygun Python fonksiyonlarını çağırır.
4. Bridge progress/log/result eventlerini JSON satırları halinde döner.
5. C# ViewModel eventleri parse eder ve UI state’ini günceller.

## UI Design (WinUI 3)

- Üst: `CommandBar` ile ana aksiyonlar
- Sol panel: Source + Partition listesi
- Orta panel: dosya ağacı (hiyerarşik)
- Sağ/alt panel: log akışı + operasyon durumu
- Alt: progress bar + sayaçlar (bad regions, errors, selected count)
- Filtreler: extension, max size, deleted/active, skip existing/archive/video

## Error Handling

- Python process başlatma hatası: UI’de bloklayıcı hata kartı + çözüm önerisi
- Bridge komut hatası: `error` event + operation summary
- Long-running cancellation: `stop` token + bridge tarafında cooperative stop
- Disk I/O hatası: mevcut zero-fill/safe-read stratejileri korunur

## Packaging and Runtime

- WinUI app modeli: **unpackaged CLI-friendly** geliştirme döngüsü
- Python runtime: mevcut `.venv` varsa onu kullan; yoksa `py -3` fallback
- `pytsk3` kontrolü startup health check ile yapılır

## Validation Plan

1. `dotnet build` ile WinUI projesi derlenir.
2. Python bridge smoke test çalıştırılır (`list_disks`/`--health`).
3. WinUI launch doğrulanır (gerçek top-level pencere).
4. En az bir operasyon akışı test edilir (disk listesi + partition scan).

## Acceptance Criteria

- Arayüz tamamen WinUI 3’tür (Tkinter kullanılmaz).
- Uygulama açılır, kullanıcı etkileşimi ile disk/scan/recovery komutları çalışır.
- Log/progress canlı akar.
- Build ve launch doğrulama çıktıları temizdir.
