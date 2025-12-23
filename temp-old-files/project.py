import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import pytsk3
import threading
import time
import os
import pickle
import queue
import binascii
import struct
import ctypes  # Windows yönetici kontrolü için
from datetime import datetime

# --- CONFIG & CONSTANTS ---
SECTOR_SIZE = 512
BLOCK_SIZE = 4096
MAX_SKIP_SIZE = 1024 * 1024 * 100  # 100 MB Max Atlama
MAP_FILE = "pydde_sector.map"
LOG_FILE = "pydde_debug.log"

# --- CORE 1: DURUM YÖNETİMİ & MAP (DDEU Logic) ---
class RecoveryState:
    def __init__(self):
        self.bad_sectors = set()
        self.skip_size = BLOCK_SIZE
        self.is_alive = True
        self.stop_requested = False
        self.consecutive_errors = 0
        self.load_map()

    def load_map(self):
        if os.path.exists(MAP_FILE):
            try:
                with open(MAP_FILE, "rb") as f:
                    self.bad_sectors = pickle.load(f)
            except: pass

    def save_map(self):
        try:
            with open(MAP_FILE, "wb") as f:
                pickle.dump(self.bad_sectors, f)
        except: pass

    def register_error(self, offset):
        """
        Adaptive Sector Skipping Logic:
        Hata alındığında atlama boyutunu üssel olarak artırır.
        """
        self.bad_sectors.add(offset)
        self.consecutive_errors += 1
        
        # Exponential Backoff: Hata arttıkça atlama boyutu büyür
        self.skip_size = min(self.skip_size * 2, MAX_SKIP_SIZE)
        
        if len(self.bad_sectors) % 50 == 0:
            self.save_map()

    def register_success(self):
        """Başarılı okumada atlama stratejisini sıfırla."""
        if self.consecutive_errors > 0:
            self.consecutive_errors = 0
            self.skip_size = BLOCK_SIZE

STATE = RecoveryState()

# --- CORE 2: SMART I/O ENGINE (Windows Compatible) ---
class SmartDiskHandle(pytsk3.Img_Info):
    def __init__(self, path, log_queue=None):
        self._path = path
        self._log_queue = log_queue
        # Windows'ta aynı dosya handle'ını birden çok thread kullanırsa seek() karışır.
        # Bu yüzden bir kilit (Lock) mekanizması ekliyoruz.
        self._lock = threading.Lock()
        
        try:
            # Windows için 'rb' (Read Binary) modunda açıyoruz.
            self._handle = open(path, "rb")
            
            # Disk boyutunu hesapla
            self._handle.seek(0, 2)
            self._size = self._handle.tell()
            self._handle.seek(0)
            
        except OSError as e:
            if log_queue:
                log_queue.put(("CRITICAL", f"Disk Erişim Hatası: {e}"))
            raise e
            
        super().__init__(url=path)

    def get_size(self):
        return self._size

    def read(self, offset, size):
        """
        Windows Uyumlu Thread-Safe Okuma.
        os.pread yerine Lock + Seek + Read kullanılır.
        """
        if not STATE.is_alive or STATE.stop_requested:
            return b"\x00" * size

        # Harita Kontrolü (Daha önce bozuk işaretlendiyse okuma)
        if offset in STATE.bad_sectors:
            return b"\x00" * size

        try:
            with self._lock:  # Başka thread'in araya girmesini engelle
                self._handle.seek(offset)
                data = self._handle.read(size)
            
            if len(data) < size:
                # Disk sonu veya okuma hatası, kalanı 0 ile doldur
                data += b"\x00" * (size - len(data))
            
            STATE.register_success()
            return data

        except OSError as e:
            # DDEU Hata Yönetimi
            STATE.register_error(offset)
            msg = f"BAD SECTOR @ {offset}. Atlanıyor: {STATE.skip_size} byte."
            
            if self._log_queue:
                self._log_queue.put(("bad_sector", msg))
            
            # Hata durumunda programı çökertme, 0 döndür
            return b"\x00" * size

    def close(self):
        try:
            self._handle.close()
        except: pass


import time


class RobustExporter:
    def __init__(self, fs_info, log_queue):
        self.fs = fs_info
        self.log_queue = log_queue
        self.stop_signal = False

        # SSD optimizasyonu için 4KB okuma yapısı
        self.cluster_size = 4096
        self.base_skip_size = 1024 * 1024  # 1MB
        self.max_skip_size = 1024 * 1024 * 50  # 50MB
        self.cooldown_time = 2.0

        # Isınma/Kilitlenme önleyici parametreler
        self.consecutive_errors = 0

    def export_file(self, inode_addr, output_path):
        try:
            f = self.fs.open_meta(inode=inode_addr)
            file_size = int(f.info.meta.size or 0)

            name = "Unknown_File"
            if hasattr(f.info.name, "name"):
                try:
                    name = f.info.name.name.decode("utf-8")
                except Exception:
                    name = "Unknown_File"
        except Exception as e:
            self.log_queue.put(("ERROR", f"Dosya Metadata Okunamadi (Inode: {inode_addr}): {e}"))
            return False

        self.log_queue.put(("INFO", f"Isleniyor: {name} ({file_size / 1024:.2f} KB)"))

        try:
            with open(output_path, "wb") as out_file:
                current_offset = 0
                consecutive_errors = 0
                current_skip = self.base_skip_size

                while current_offset < file_size:
                    if STATE.stop_requested:
                        self.log_queue.put(("WARNING", "Islem durduruldu."))
                        return False

                    to_read = min(self.cluster_size, file_size - current_offset)
                    try:
                        data = f.read_random(current_offset, to_read)
                        out_file.write(data if data else b"\x00" * to_read)
                        if consecutive_errors > 0:
                            consecutive_errors = 0
                            current_skip = self.base_skip_size
                        current_offset += to_read
                    except Exception:
                        out_file.write(b"\x00" * to_read)
                        consecutive_errors += 1

                        wait_time = self.cooldown_time * (1 if consecutive_errors < 5 else 2)
                        self.log_queue.put(
                            ("CRITICAL", f"G/C Hatasi @ {current_offset}. Disk dinlendiriliyor ({wait_time}s)...")
                        )
                        time.sleep(wait_time)

                        if consecutive_errors >= 2:
                            skip_amount = min(current_skip, file_size - (current_offset + to_read))
                            if skip_amount > 0:
                                self.log_queue.put(
                                    ("bad_sector", f"Bozuk Bolge! {skip_amount/1024:.0f}KB Atlaniyor ve 0 ile dolduruluyor.")
                                )
                                written_zeros = 0
                                zero_chunk = 1024 * 1024
                                while written_zeros < skip_amount:
                                    z_size = min(zero_chunk, skip_amount - written_zeros)
                                    out_file.write(b"\x00" * z_size)
                                    written_zeros += z_size

                                current_offset += skip_amount
                                current_skip = min(current_skip * 2, self.max_skip_size)
                        current_offset += to_read

            return True
        except Exception as e:
            self.log_queue.put(("CRITICAL", f"Dosya Yazma Hatasi: {e}"))
            return False

# --- GUI APPLICATION ---
class PyDDE_Ultimate:
    def __init__(self, root):
        self.root = root
        self.root.title("PyDDE Ultimate - Windows Forensic Recovery")
        self.root.geometry("1280x850")
        
        self.log_queue = queue.Queue()
        self.current_img = None
        self.disk_path = ""
        self.node_metadata = {} 
        
        self._setup_ui()
        self._start_log_consumer()

    def _setup_ui(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        # --- TOOLBAR ---
        toolbar = ttk.Frame(self.root, padding=5)
        toolbar.pack(fill=tk.X)
        
        ttk.Label(toolbar, text="Hedef Disk:").pack(side=tk.LEFT)
        self.entry_disk = ttk.Entry(toolbar, width=25)
        # Windows formatı: \\.\PhysicalDrive1
        self.entry_disk.insert(0, r"\\.\PhysicalDrive1") 
        self.entry_disk.pack(side=tk.LEFT, padx=5)

        ttk.Button(toolbar, text="BAĞLAN", command=self.action_connect).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="RAW TARA", command=self.action_scan).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="MFT ANALİZİ", command=self.action_parse_mft).pack(side=tk.LEFT, padx=2)
        
        btn_stop = tk.Button(toolbar, text="ACİL DURDUR", bg="#8B0000", fg="white", command=self.action_stop)
        btn_stop.pack(side=tk.RIGHT, padx=10)

        # --- MAIN PANES ---
        paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # LEFT: Partitions & Hex
        left_frame = ttk.Notebook(paned)
        paned.add(left_frame, weight=1)

        self.list_parts = tk.Listbox(left_frame, bg="#202020", fg="#00FF00", font=("Consolas", 10))
        self.list_parts.bind('<<ListboxSelect>>', self.on_partition_select)
        left_frame.add(self.list_parts, text="Partition Table")

        self.txt_hex = tk.Text(left_frame, bg="#101010", fg="#00FF00", font=("Courier New", 9))
        left_frame.add(self.txt_hex, text="Hex/ASCII View")

        # RIGHT: File Tree
        right_frame = ttk.LabelFrame(paned, text="MFT File Structure (NTFS)")
        paned.add(right_frame, weight=3)

        cols = ("size", "status", "inode")
        self.tree = ttk.Treeview(right_frame, columns=cols, show="tree headings")
        self.tree.heading("#0", text="Dosya Adı")
        self.tree.heading("size", text="Boyut (B)")
        self.tree.heading("status", text="Durum")
        self.tree.heading("inode", text="MFT ID")
        self.tree.column("inode", width=60)
        self.tree.column("size", width=80)
        
        ysb = ttk.Scrollbar(right_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=ysb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ysb.pack(side=tk.RIGHT, fill=tk.Y)

        # Context Menu
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="SEÇİLİ DOSYAYI KURTAR", command=self.recover_selected_file)
        self.tree.bind("<Button-3>", self.show_context_menu)

        # --- LOG ---
        log_frame = ttk.LabelFrame(self.root, text="Olay Günlüğü", height=150)
        log_frame.pack(fill=tk.X, padx=5, pady=5)
        self.txt_log = tk.Text(log_frame, height=8, bg="black", fg="white", font=("Consolas", 9))
        self.txt_log.pack(fill=tk.BOTH)
        
        self.txt_log.tag_config("WARNING", foreground="orange")
        self.txt_log.tag_config("CRITICAL", foreground="red", background="#200000")
        self.txt_log.tag_config("bad_sector", foreground="yellow")
        self.txt_log.tag_config("INFO", foreground="white")

    # --- ACTIONS ---

    def action_stop(self):
        STATE.stop_requested = True
        self.log("DURDURMA İSTEĞİ: İşlemler askıya alınıyor...", "CRITICAL")

    def action_connect(self):
        STATE.stop_requested = False
        self.disk_path = self.entry_disk.get()
        
        # Windows Path Kontrolü
        if not self.disk_path.startswith(r"\\.\PhysicalDrive") and ":" not in self.disk_path:
             messagebox.showwarning("Uyarı", "Windows'ta fiziksel disk yolu genellikle '\\\\.\\PhysicalDrive1' şeklindedir.\nİmaj dosyası ise tam yol giriniz.")

        try:
            self.current_img = SmartDiskHandle(self.disk_path, self.log_queue)
            size_gb = self.current_img.get_size() / (1024**3)
            self.log(f"Bağlantı Başarılı: {self.disk_path} ({size_gb:.2f} GB)", "INFO")
        except Exception as e:
            self.log(f"Bağlantı Hatası: {e}", "CRITICAL")
            messagebox.showerror("Erişim Hatası", f"Diske erişilemedi.\nLütfen Yönetici Olarak Çalıştırdığınızdan emin olun.\n\nHata: {e}")

    def action_scan(self):
        if not self.current_img: return
        STATE.stop_requested = False
        threading.Thread(target=self._thread_scan_raw, daemon=True).start()

    def _thread_scan_raw(self):
        self.log("Partition Taraması Başlatıldı...", "INFO")
        offset = 0
        step = 1024 * 1024  # 1MB Hızlı Atlama
        limit = self.current_img.get_size()

        while offset < limit:
            if STATE.stop_requested or not STATE.is_alive: break
            try:
                data = self.current_img.read(offset, 512)
                
                # NTFS Signature Check
                if len(data) > 10 and data[3:7] == b'NTFS':
                    msg = f"NTFS Partition | Offset: {offset}"
                    self.log_queue.put(("INFO", f"Bölüm Bulundu: {offset}"))
                    self.list_parts.insert(tk.END, msg)
                    offset += 100 * 1024 * 1024 # 100MB atla
            except: pass
            offset += step
        self.log("Tarama Tamamlandı.", "INFO")

    def on_partition_select(self, event):
        selection = self.list_parts.curselection()
        if not selection: return
        item = self.list_parts.get(selection[0])
        try:
            offset = int(item.split("Offset:")[1].strip())
            data = self.current_img.read(offset, 512)
            
            display_text = f"Offset: {offset} (Boot Sector)\n" + "-"*60 + "\n"
            
            for i in range(0, len(data), 16):
                chunk = data[i:i+16]
                hex_part = " ".join(f"{b:02X}" for b in chunk)
                # ASCII (Windows uyumlu karakter filtreleme)
                ascii_part = "".join((chr(b) if 32 <= b < 127 else ".") for b in chunk)
                display_text += f"{i:04X}  {hex_part:<48}  |{ascii_part}|\n"
            
            self.txt_hex.delete(1.0, tk.END)
            self.txt_hex.insert(tk.END, display_text)
        except Exception as e:
            self.log(f"Hex Görüntüleme Hatası: {e}", "WARNING")

    def action_parse_mft(self):
        sel = self.list_parts.curselection()
        if not sel:
            messagebox.showwarning("Uyarı", "Lütfen sol listeden bir bölüm (Partition) seçin.")
            return
        
        item = self.list_parts.get(sel[0])
        offset = int(item.split("Offset:")[1].strip())
        
        self.tree.delete(*self.tree.get_children())
        self.node_metadata = {}
        STATE.stop_requested = False
        
        threading.Thread(target=self._thread_parse_mft, args=(offset,), daemon=True).start()

    def _thread_parse_mft(self, offset):
        self.log(f"MFT Yapısı Çözümleniyor @ {offset}...", "INFO")
        try:
            # SmartDiskHandle ile FS aç
            fs = pytsk3.FS_Info(self.current_img, offset=offset)
            root = fs.open_dir(path="/")
            self._recursive_tree(fs, root, "", offset)
            self.log_queue.put(("INFO", "MFT Analizi Tamamlandı."))
        except Exception as e:
            self.log_queue.put(("CRITICAL", f"Dosya Sistemi (MFT) Hatası: {e}"))

    def _recursive_tree(self, fs, directory, path, part_offset):
        if STATE.stop_requested: return

        for entry in directory:
            try:
                if not hasattr(entry.info, "name"): continue
                name = entry.info.name.name.decode('utf-8')
                if name in [".", "..", "$MFT", "$LogFile", "$BadClus"]: continue

                meta = entry.info.meta
                status = "DELETED" if meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC else "ACTIVE"
                full_path = os.path.join(path, name)
                inode_addr = meta.addr

                # Treeview ekleme
                # GUI thread-safe olması için after kullanmıyoruz ama 
                # Tkinter, threadlerden yapılan insert işlemlerini genelde tolere eder.
                # Büyük listelerde queue kullanmak daha iyidir ama bu proje için direkt ekliyoruz.
                item_id = self.tree.insert("", "end", text=full_path, values=(meta.size, status, inode_addr))
                self.node_metadata[item_id] = (part_offset, inode_addr)

                if meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    sub_dir = entry.as_directory()
                    self._recursive_tree(fs, sub_dir, full_path, part_offset)
            except: pass

    # --- RECOVERY ENGINE ---
    def show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def recover_selected_file(self):
        selected_item = self.tree.selection()[0]
        if selected_item not in self.node_metadata:
            return

        part_offset, inode_addr = self.node_metadata[selected_item]
        file_name = self.tree.item(selected_item, "text").split("/")[-1]
        
        target_dir = filedialog.askdirectory()
        if not target_dir: return
        target_path = os.path.join(target_dir, file_name)

        threading.Thread(target=self._thread_recover_file, args=(part_offset, inode_addr, target_path), daemon=True).start()

    def _thread_recover_file(self, part_offset, inode_addr, target_path):
        self.log_queue.put(("INFO", f"Kurtarma Başladı: {target_path}"))
        
        try:
            fs = pytsk3.FS_Info(self.current_img, offset=part_offset)
            file_entry = fs.open_meta(inode=inode_addr)
            size = file_entry.info.meta.size
            
            with open(target_path, "wb") as out_file:
                offset = 0
                chunk_size = 64 * 1024 
                
                while offset < size:
                    if STATE.stop_requested: break
                    to_read = min(chunk_size, size - offset)
                    
                    try:
                        data = file_entry.read_random(offset, to_read)
                        if not data: 
                            out_file.write(b"\x00" * to_read)
                        else:
                            out_file.write(data)
                    except Exception as e:
                        self.log_queue.put(("bad_sector", f"Okuma Hatası @ {offset}"))
                        out_file.write(b"\x00" * to_read)
                    
                    offset += to_read
            
            self.log_queue.put(("INFO", f"Dosya Kaydedildi: {target_path}"))
        except Exception as e:
            self.log_queue.put(("ERROR", f"Kurtarma Başarısız: {e}"))

    # --- LOG SYSTEM ---
    def _start_log_consumer(self):
        try:
            while True:
                level, msg = self.log_queue.get_nowait()
                self.log(msg, level)
        except queue.Empty:
            pass
        self.root.after(100, self._start_log_consumer)

    def log(self, msg, level="INFO"):
        ts = datetime.now().strftime("%H:%M:%S")
        self.txt_log.insert(tk.END, f"[{ts}] [{level}] {msg}\n", level)
        self.txt_log.see(tk.END)

if __name__ == "__main__":
    # --- WINDOWS ADMIN KONTROLÜ ---
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except:
        is_admin = False

    if not is_admin:
        print("\n" + "!"*60)
        print("!!! HATA: BU PROGRAM YÖNETİCİ HAKLARI GEREKTİRİR !!!")
        print("Disklere fiziksel erişim için lütfen terminali")
        print("'Yönetici Olarak Çalıştır' (Run as Administrator) seçeneği ile açın.")
        print("!"*60 + "\n")
        input("Çıkmak için Enter'a basın...")
        exit(1)

    root = tk.Tk()
    app = PyDDE_Ultimate(root)
    root.mainloop()
