# PyDDEU WinUI 3 Hybrid Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Python recovery motorunu koruyup tamamen WinUI 3 arayüzlü çalışan bir desktop uygulama teslim etmek.

**Architecture:** WinUI 3 C# uygulaması frontend olarak çalışır; Python bridge process üzerinden mevcut `pyddeu` modüllerine komut gönderir. JSON satır tabanlı event protokolü ile log/progress/result WinUI state’e taşınır.

**Tech Stack:** WinUI 3 (.NET 10), C#, Windows App SDK template (`dotnet new winui`), Python 3.11+, `pyddeu` core modules.

---

### Task 1: WinUI Scaffold ve Build Tabanı

**Files:**
- Create: `winui/PyDDEU.WinUI/*` (template çıktısı)
- Modify: `winui/PyDDEU.WinUI/PyDDEU.WinUI.csproj`

**Step 1: Scaffold üret**

Run: `dotnet new winui -o winui/PyDDEU.WinUI`
Expected: proje dosyaları oluşur.

**Step 2: İlk build**

Run: `dotnet build winui/PyDDEU.WinUI/PyDDEU.WinUI.csproj`
Expected: derleme başarılı.

**Step 3: Commit**

```bash
git add winui/PyDDEU.WinUI
git commit -m "chore: scaffold WinUI 3 host app"
```

### Task 2: Python Bridge Protokolü

**Files:**
- Create: `pyddeu/winui_bridge.py`
- Test: `tests/test_winui_bridge_protocol.py`

**Step 1: Write failing test**

Bridge’in `--health` çağrısında geçerli JSON döndürmesini bekleyen test yaz.

**Step 2: Run test to verify red**

Run: `pytest tests/test_winui_bridge_protocol.py -v`
Expected: FAIL (dosya/komut henüz yok).

**Step 3: Minimal implementation**

`--health`, `list_disks`, `scan_partitions` komutlarını stdin/stdout JSON ile implemente et.

**Step 4: Run test to verify green**

Run: `pytest tests/test_winui_bridge_protocol.py -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add pyddeu/winui_bridge.py tests/test_winui_bridge_protocol.py
git commit -m "feat: add python bridge for winui host"
```

### Task 3: Bridge’de Uzun Süren Operasyonlar

**Files:**
- Modify: `pyddeu/winui_bridge.py`
- Test: `tests/test_winui_bridge_operations.py`

**Step 1: Write failing tests**

`deep_ntfs_scan`, `mft_scan`, `file_carve`, `create_image`, `stop` davranışları için protocol-level test yaz.

**Step 2: Verify red**

Run: `pytest tests/test_winui_bridge_operations.py -v`
Expected: FAIL.

**Step 3: Minimal implementation**

Uzun süren komutları worker thread ile çalıştır, progress/log/result eventleri yayınla.

**Step 4: Verify green**

Run: `pytest tests/test_winui_bridge_operations.py -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add pyddeu/winui_bridge.py tests/test_winui_bridge_operations.py
git commit -m "feat: bridge long-running operations and cancellation"
```

### Task 4: WinUI Domain Model + Process Host

**Files:**
- Create: `winui/PyDDEU.WinUI/Models/*.cs`
- Create: `winui/PyDDEU.WinUI/Services/PythonBridgeClient.cs`
- Test: `winui/PyDDEU.WinUI.Tests/PythonBridgeClientTests.cs`

**Step 1: Write failing test**

JSON line parse + event dispatch davranışı için test yaz.

**Step 2: Verify red**

Run: `dotnet test winui/PyDDEU.WinUI.Tests/PyDDEU.WinUI.Tests.csproj`
Expected: FAIL.

**Step 3: Minimal implementation**

Process start/stop, command send, event parse, cancellation desteği ekle.

**Step 4: Verify green**

Run: `dotnet test winui/PyDDEU.WinUI.Tests/PyDDEU.WinUI.Tests.csproj`
Expected: PASS.

**Step 5: Commit**

```bash
git add winui/PyDDEU.WinUI/Models winui/PyDDEU.WinUI/Services winui/PyDDEU.WinUI.Tests
git commit -m "feat: add csharp bridge client and event models"
```

### Task 5: Main UI Shell (CommandBar + Panes + Log/Status)

**Files:**
- Modify: `winui/PyDDEU.WinUI/MainWindow.xaml`
- Modify: `winui/PyDDEU.WinUI/MainWindow.xaml.cs`
- Create: `winui/PyDDEU.WinUI/ViewModels/MainViewModel.cs`

**Step 1: Write failing test**

ViewModel command executionunda state geçişlerini (Idle->Running->Completed) test et.

**Step 2: Verify red**

Run: `dotnet test winui/PyDDEU.WinUI.Tests/PyDDEU.WinUI.Tests.csproj`
Expected: FAIL.

**Step 3: Minimal implementation**

Partition listesi, file tree, log panel, progress ve toolbar komutlarını bağla.

**Step 4: Verify green**

Run: `dotnet test winui/PyDDEU.WinUI.Tests/PyDDEU.WinUI.Tests.csproj`
Expected: PASS.

**Step 5: Commit**

```bash
git add winui/PyDDEU.WinUI/MainWindow.xaml winui/PyDDEU.WinUI/MainWindow.xaml.cs winui/PyDDEU.WinUI/ViewModels
git commit -m "feat: build winui shell and command workflows"
```

### Task 6: Recovery ve Export Akışlarının UI Entegrasyonu

**Files:**
- Modify: `winui/PyDDEU.WinUI/ViewModels/MainViewModel.cs`
- Modify: `winui/PyDDEU.WinUI/Models/*.cs`
- Test: `winui/PyDDEU.WinUI.Tests/MainViewModelRecoveryTests.cs`

**Step 1: Write failing tests**

`recover_selected`, `recover_folder`, filtre parametrelerinin doğru bridge payload üretimini test et.

**Step 2: Verify red**

Run: `dotnet test winui/PyDDEU.WinUI.Tests/PyDDEU.WinUI.Tests.csproj`
Expected: FAIL.

**Step 3: Minimal implementation**

Seçim, filtre ve output path kontrollerini tamamla; kullanıcıya hata mesajlarını göster.

**Step 4: Verify green**

Run: `dotnet test winui/PyDDEU.WinUI.Tests/PyDDEU.WinUI.Tests.csproj`
Expected: PASS.

**Step 5: Commit**

```bash
git add winui/PyDDEU.WinUI/ViewModels winui/PyDDEU.WinUI/Models winui/PyDDEU.WinUI.Tests
git commit -m "feat: wire recovery/export actions to bridge"
```

### Task 7: Çalıştırma Yardımcıları ve Dokümantasyon

**Files:**
- Create: `scripts/run_winui.ps1`
- Modify: `README.md`

**Step 1: Write failing check**

Run script smoke check: `powershell -ExecutionPolicy Bypass -File scripts/run_winui.ps1 -WhatIf`
Expected: eksik script nedeniyle FAIL.

**Step 2: Minimal implementation**

Script içinde Python bridge health check + WinUI launch adımlarını ekle.

**Step 3: Verify green**

Run: `powershell -ExecutionPolicy Bypass -File scripts/run_winui.ps1`
Expected: bridge health + WinUI launch.

**Step 4: Commit**

```bash
git add scripts/run_winui.ps1 README.md
git commit -m "docs: add winui run workflow and usage notes"
```

### Task 8: E2E Verification (Mandatory)

**Files:**
- Modify: `docs/plans/2026-03-04-winui3-hybrid-implementation.md` (verification notes)

**Step 1: Build verification**

Run: `dotnet build winui/PyDDEU.WinUI/PyDDEU.WinUI.csproj`
Expected: PASS.

**Step 2: Python bridge verification**

Run: `python -m pyddeu.winui_bridge --health`
Expected: JSON healthy response.

**Step 3: Launch verification**

Run: WinUI app executable; gerçek pencere açıldığını doğrula.
Expected: responsive top-level window.

**Step 4: Functional smoke**

Run: `list_disks` + `scan_partitions` komutlarını UI’den tetikle.
Expected: sonuçlar listelenir, log/progress akar.

**Step 5: Final commit**

```bash
git add -A
git commit -m "feat: deliver complete winui3 desktop app with python recovery backend"
```
