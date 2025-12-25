# ==========================================
# GÜVENLİK VE BAŞLANGIÇ AYARLARI
# ==========================================
# İşlem bazlı Execution Policy Bypass
Set-ExecutionPolicy Bypass -Scope Process -Force

# Hata ayıklama modunu sessize al
$ErrorActionPreference = "SilentlyContinue"

# Bilgisayar bilgilerini al
$Hostname = $env:COMPUTERNAME
$IPAddress = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike "*Loopback*" -and $_.InterfaceAlias -notlike "*vEthernet*"}).IPAddress[0]
if (-not $IPAddress) { $IPAddress = "No-IP" }

# Rapor Dosyası: Hostname ve IP içerir
$ReportFile = ".\Full_Analiz_${Hostname}_${IPAddress}.txt"

# Dosya varsa temizle, yoksa oluştur
New-Item -Path $ReportFile -ItemType File -Force | Out-Null

Write-Host "Derinlemesine sistem analizi başlatılıyor..." -ForegroundColor Cyan
Write-Host "Rapor Dosyası: $ReportFile" -ForegroundColor Yellow

# ==========================================
# YARDIMCI FONKSİYON (LOGLAMA)
# ==========================================
function Log-Section {
    param (
        [string]$Title,
        [scriptblock]$Command
    )
    
    $Header = @"
`n
################################################################################
$Title
TARİH: $(Get-Date)
################################################################################
"@
    Add-Content -Path $ReportFile -Value $Header
    
    try {
        # Komut çıktısını al, tablo formatını koruyarak stringe çevir ve dosyaya ekle
        $Result = & $Command
        if ($Result) {
            $Result | Format-Table -AutoSize | Out-String -Width 4096 | Add-Content -Path $ReportFile
        } else {
            Add-Content -Path $ReportFile -Value "[-] Veri bulunamadı veya erişim yetkisi yok."
        }
    } catch {
        Add-Content -Path $ReportFile -Value "[!] Hata oluştu: $_"
    }
    
    Write-Host "[OK] $Title tamamlandı." -ForegroundColor Green
}

# ==========================================
# 1. SİSTEM ÖZETİ
# ==========================================
Log-Section "SİSTEM ÖZETİ" {
    $CS = Get-CimInstance Win32_ComputerSystem
    $OS = Get-CimInstance Win32_OperatingSystem
    [PSCustomObject]@{
        Hostname      = $CS.Name
        Manufacturer  = $CS.Manufacturer
        Model         = $CS.Model
        OS            = $OS.Caption
        LastBoot      = $OS.LastBootUpTime
        TotalRAM_GB   = [math]::round($CS.TotalPhysicalMemory / 1GB, 2)
    }
}

# ==========================================
# 2. AĞ BAĞLANTILARI VE PROCESS İLİŞKİSİ (KRİTİK BÖLÜM)
# ==========================================
# Burada her bağlantının PID'sini alıp Get-Process ile eşleştiriyoruz.
Log-Section "NETWORK BAĞLANTILARI VE İLGİLİ PROCESSLER (KİM BAĞLANIYOR?)" {
    Get-NetTCPConnection | Select-Object `
        @{Name='LocalIP';Expression={$_.LocalAddress}},
        @{Name='LocalPort';Expression={$_.LocalPort}},
        @{Name='RemoteIP';Expression={$_.RemoteAddress}},
        @{Name='RemotePort';Expression={$_.RemotePort}},
        State,
        OwningProcess,
        @{Name='ProcessName';Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}},
        @{Name='ProcessPath';Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}} |
        Sort-Object State, ProcessName
}

# ==========================================
# 3. DNS ÖNBELLEĞİ (GİDİLEN ADRESLER)
# ==========================================
Log-Section "DNS CACHE (SON ERİŞİLEN DOMAINLER)" {
    Get-DnsClientCache | Select-Object Entry, RecordName, Data, Type, Status | Sort-Object Entry
}

# ==========================================
# 4. TÜM ÇALIŞAN PROCESSLER (TAM LİSTE)
# ==========================================
Log-Section "SİSTEMDE ÇALIŞAN TÜM İŞLEMLER (PROCESS DUMP)" {
    Get-Process | Sort-Object Id | Select-Object `
        Id,
        ProcessName,
        @{Name='Memory(MB)';Expression={[math]::round($_.WorkingSet / 1MB, 2)}},
        StartTime,
        Path,
        Description,
        MainWindowTitle # Varsa açık pencere başlığı (Örn: Chrome sekme adı)
}

# ==========================================
# 5. DONANIM DETAYLARI (RAM & ANAKART)
# ==========================================
Log-Section "RAM SLOTLARI VE ANAKART DETAYI" {
    Get-CimInstance Win32_PhysicalMemory | Select-Object BankLabel, Capacity, Speed, Manufacturer, PartNumber
    Write-Output "`n--- ANAKART ---"
    Get-CimInstance Win32_BaseBoard | Select-Object Manufacturer, Product, SerialNumber
}

# ==========================================
# 6. SİSTEM HATALARI (EVENT LOG - SON 20)
# ==========================================
# Log dosyasını yüzlerce MB yapmamak için hatalarda son 20 ile sınırlı kalmak iyidir.
Log-Section "KRİTİK SİSTEM HATALARI (SON 20)" {
    Get-EventLog -LogName System -EntryType Error -Newest 20 | Select-Object TimeGenerated, Source, EventID, Message
}

Write-Host "`n=========================================" -ForegroundColor Green
Write-Host "Analiz Tamamlandı." -ForegroundColor Green
Write-Host "Çıktı dosyası: $ReportFile" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Green
