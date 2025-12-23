from __future__ import annotations

import queue
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import time

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

try:
    import pytsk3
except Exception as e:  # pragma: no cover
    pytsk3 = None  # type: ignore[assignment]
    _PYTSK3_IMPORT_ERROR = e
else:
    _PYTSK3_IMPORT_ERROR = None

from .io import list_sources, open_source
from .mft import build_paths, scan_and_parse_mft
from .partitions import Partition, carve_ntfs_partitions, scan_partitions
from .platform import IS_WINDOWS, format_source_hint, is_admin
from .state import RecoveryState
from .tskimg import DDEUImg
from .carve import carve_signatures
from .monitor import start_monitor
from .ntfs_boot import parse_ntfs_boot_sector
from .recover import recover_nonresident_runs
from .imager import create_image
from .exporter import RobustExporter


@dataclass(frozen=True)
class _TreeItem:
    path: str
    size: int
    status: str
    inode: int
    part_offset: int
    is_dir: bool
    resident_data: bytes | None = None
    data_runs: list[tuple[int | None, int]] | None = None
    data_size: int | None = None
    cluster_size: int | None = None


class PyDDEUGui:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("PyDDEU - Forensic Recovery (NTFS)")
        self.root.geometry("1280x850")

        self.log_queue: "queue.Queue[tuple[str, str]]" = queue.Queue()
        self.ui_queue: "queue.Queue[object]" = queue.Queue()

        self.source_path: str = ""
        self.source = None
        self._monitor_thread = None
        self.output_root = _default_output_root()
        self._refresh_inflight = False
        self._last_refresh_ts = 0.0

        self.state = RecoveryState(map_path=Path("pyddeu.map.json"))
        self.partitions: list[Partition] = []
        self.node_metadata: dict[str, tuple[int, int, bool]] = {}
        self._resident_cache: dict[str, bytes] = {}
        self._nonresident_cache: dict[str, tuple[int, int, list[tuple[int | None, int]], int | None]] = {}

        self._setup_ui()
        self._log_file = None
        try:
            self._log_file = open("pyddeu_debug.log", "a", encoding="utf-8", buffering=1)
        except Exception:
            self._log_file = None
        self._start_log_consumer()
        self._start_ui_consumer()
        self._start_status_updater()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _on_close(self) -> None:
        self.state.stop_requested = True
        try:
            if self.source:
                self.source.close()
        except Exception:
            pass
        try:
            if self._log_file:
                self._log_file.close()
        except Exception:
            pass
        self.root.destroy()

    def _setup_ui(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        toolbar = ttk.Frame(self.root, padding=5)
        toolbar.pack(fill=tk.X)

        ttk.Label(toolbar, text="Source:").pack(side=tk.LEFT)
        self.entry_source = ttk.Entry(toolbar, width=40)
        self.entry_source.insert(0, format_source_hint())
        self.entry_source.pack(side=tk.LEFT, padx=5)

        ttk.Label(toolbar, text="Output:").pack(side=tk.LEFT, padx=(10, 0))
        self.entry_output = ttk.Entry(toolbar, width=28)
        self.entry_output.insert(0, str(self.output_root))
        self.entry_output.pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="Browse…", command=self.action_browse_output).pack(side=tk.LEFT, padx=2)

        source_btn = ttk.Menubutton(toolbar, text="Source")
        source_btn.pack(side=tk.LEFT, padx=2)
        source_menu = tk.Menu(source_btn, tearoff=0)
        source_btn["menu"] = source_menu
        source_menu.add_command(label="Browse Image…", command=self.action_browse_image)
        source_menu.add_command(label="List Disks", command=self.action_list_disks)
        source_menu.add_separator()
        source_menu.add_command(label="Connect", command=self.action_connect)
        source_menu.add_command(label="Scan Partitions", command=self.action_scan_partitions)
        source_menu.add_command(label="Parse NTFS", command=self.action_parse_fs)

        actions_btn = ttk.Menubutton(toolbar, text="Actions")

        actions_btn.pack(side=tk.LEFT, padx=2)

        actions_menu = tk.Menu(actions_btn, tearoff=0)

        actions_btn["menu"] = actions_menu

        actions_menu.add_command(label="MFT Scan (RAW)", command=self.action_mft_scan)

        actions_menu.add_command(label="File Carve (RAW)", command=self.action_file_carve)

        actions_menu.add_command(label="Deep Scan (NTFS)", command=self.action_deep_ntfs_scan)

        actions_menu.add_separator()

        actions_menu.add_command(label="Create Image", command=self.action_create_image)

        actions_menu.add_command(label="Image Selected Part", command=self.action_image_selected_partition)

        actions_menu.add_separator()

        actions_menu.add_command(label="Export All", command=self.action_export_all)

        actions_menu.add_command(label="Recover All (Zero-fill)", command=self.action_recover_all)

        actions_menu.add_command(label="Recover All (MFT)", command=self.action_recover_all_mft)


        btn_stop = tk.Button(
            toolbar, text="STOP", bg="#8B0000", fg="white", command=self.action_stop
        )
        btn_stop.pack(side=tk.RIGHT, padx=10)

        paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        left_frame = ttk.Notebook(paned)
        paned.add(left_frame, weight=1)

        self.list_parts = tk.Listbox(
            left_frame, bg="#202020", fg="#00FF00", font=("Consolas", 10)
        )
        self.list_parts.bind("<<ListboxSelect>>", self.on_partition_select)
        left_frame.add(self.list_parts, text="Partitions")

        self.txt_hex = tk.Text(left_frame, bg="#101010", fg="#00FF00", font=("Courier New", 9))
        left_frame.add(self.txt_hex, text="Hex/ASCII")

        right_frame = ttk.LabelFrame(paned, text="File Tree (pytsk3 / NTFS)")
        paned.add(right_frame, weight=3)

        cols = ("size", "status", "inode")
        self.tree = ttk.Treeview(right_frame, columns=cols, show="tree headings")
        self.tree.heading("#0", text="Path")
        self.tree.heading("size", text="Size (B)")
        self.tree.heading("status", text="Status")
        self.tree.heading("inode", text="MFT ID")
        self.tree.column("inode", width=70)
        self.tree.column("size", width=110)

        ysb = ttk.Scrollbar(right_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=ysb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ysb.pack(side=tk.RIGHT, fill=tk.Y)

        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Recover selected file", command=self.recover_selected_file)
        self.tree.bind("<Button-3>", self.show_context_menu)

        log_frame = ttk.LabelFrame(self.root, text="Log", height=150)
        log_frame.pack(fill=tk.X, padx=5, pady=5)

        log_controls = ttk.Frame(log_frame)
        log_controls.pack(fill=tk.X)
        self.var_autoscroll = tk.BooleanVar(value=True)
        self.var_pause = tk.BooleanVar(value=False)
        ttk.Checkbutton(log_controls, text="Auto-scroll", variable=self.var_autoscroll).pack(side=tk.LEFT)
        ttk.Checkbutton(log_controls, text="Pause", variable=self.var_pause).pack(side=tk.LEFT, padx=(10, 0))
        ttk.Button(log_controls, text="Open log file", command=self.action_open_logfile).pack(
            side=tk.RIGHT
        )

        log_inner = ttk.Frame(log_frame)
        log_inner.pack(fill=tk.BOTH, expand=True)
        self.txt_log = tk.Text(log_inner, height=10, bg="black", fg="white", font=("Consolas", 9), wrap="none")
        ysb = ttk.Scrollbar(log_inner, orient=tk.VERTICAL, command=self.txt_log.yview)
        self.txt_log.configure(yscrollcommand=ysb.set)
        self.txt_log.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ysb.pack(side=tk.RIGHT, fill=tk.Y)

        self.txt_log.tag_config("WARNING", foreground="orange")
        self.txt_log.tag_config("CRITICAL", foreground="red", background="#200000")
        self.txt_log.tag_config("bad_sector", foreground="yellow")
        self.txt_log.tag_config("INFO", foreground="white")

        status_frame = ttk.Frame(self.root, padding=(5, 0, 5, 5))
        status_frame.pack(fill=tk.X)
        self.lbl_status = ttk.Label(status_frame, text="Idle")
        self.lbl_status.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.prog = ttk.Progressbar(status_frame, mode="determinate")
        self.prog.pack(side=tk.RIGHT, fill=tk.X, expand=False)
        self.prog.configure(length=300, maximum=100)

        filter_frame = ttk.Frame(self.root, padding=(5, 0, 5, 5))
        filter_frame.pack(fill=tk.X)
        ttk.Label(filter_frame, text="Export filter (extensions, comma):").pack(side=tk.LEFT)
        self.entry_ext = ttk.Entry(filter_frame, width=35)
        self.entry_ext.insert(0, "jpg,jpeg,png,pdf,doc,docx,xls,xlsx,txt")
        self.entry_ext.pack(side=tk.LEFT, padx=5)

        ttk.Label(filter_frame, text="Max size (MB, 0=off):").pack(side=tk.LEFT, padx=(10, 0))
        self.entry_max_mb = ttk.Entry(filter_frame, width=8)
        self.entry_max_mb.insert(0, "512")
        self.entry_max_mb.pack(side=tk.LEFT, padx=5)

        self.var_skip_archives = tk.BooleanVar(value=True)
        self.var_skip_existing = tk.BooleanVar(value=True)
        self.var_export_deleted = tk.BooleanVar(value=True)
        self.var_export_active = tk.BooleanVar(value=True)

        filter_opts_btn = ttk.Menubutton(filter_frame, text="Filter Options")
        filter_opts_btn.pack(side=tk.LEFT, padx=(10, 0))
        filter_opts_menu = tk.Menu(filter_opts_btn, tearoff=0)
        filter_opts_btn["menu"] = filter_opts_menu
        filter_opts_menu.add_checkbutton(
            label="Skip archives (.zip/.rar/.7z/...)", variable=self.var_skip_archives
        )
        filter_opts_menu.add_checkbutton(
            label="Skip existing (already recovered)", variable=self.var_skip_existing
        )
        filter_opts_menu.add_separator()
        filter_opts_menu.add_checkbutton(label="Include Deleted", variable=self.var_export_deleted)
        filter_opts_menu.add_checkbutton(label="Include Active", variable=self.var_export_active)

    def _log(self, level: str, msg: str) -> None:
        self.log_queue.put((level, msg))

    def _maybe_refresh_source_async(self, reason: str) -> None:
        """
        Best-effort handle refresh after controller resets without blocking the UI.
        """
        if self._refresh_inflight:
            return
        src = getattr(self, "source", None)
        refresh = getattr(src, "refresh", None) if src is not None else None
        if not callable(refresh):
            return

        now = time.time()
        if now - float(getattr(self, "_last_refresh_ts", 0.0)) < 8.0:
            return
        self._refresh_inflight = True
        self._last_refresh_ts = now

        def worker() -> None:
            try:
                self._log("WARNING", f"Refreshing disk handle (reason: {reason})")
                refresh()
                self._log("INFO", "Disk handle refreshed.")
            except Exception as e:
                self._log("WARNING", f"Disk handle refresh failed: {e}")
            finally:
                self._refresh_inflight = False

        threading.Thread(target=worker, daemon=True).start()

    def _start_log_consumer(self) -> None:
        try:
            while True:
                level, msg = self.log_queue.get_nowait()
                ts = datetime.now().strftime("%H:%M:%S")
                if not self.var_pause.get():
                    self.txt_log.insert(tk.END, f"[{ts}] [{level}] {msg}\n", level)
                    if self.var_autoscroll.get():
                        self.txt_log.see(tk.END)
                if self._log_file:
                    try:
                        self._log_file.write(f"[{ts}] [{level}] {msg}\n")
                    except Exception:
                        pass
                if level == "CRITICAL":
                    low = str(msg).lower()
                    if "eventlog:" in low and ("reset to device" in low or "device" in low and "was issued" in low):
                        self._maybe_refresh_source_async("eventlog reset")
                # keep UI responsive: cap log lines
                try:
                    lines = int(self.txt_log.index("end-1c").split(".")[0])
                    if lines > 5000:
                        self.txt_log.delete("1.0", "1000.0")
                except Exception:
                    pass
        except queue.Empty:
            pass
        self.root.after(100, self._start_log_consumer)

    def _start_status_updater(self) -> None:
        try:
            status = getattr(self, "_status_text", "Idle")
            pct = getattr(self, "_status_pct", None)
            if pct is None:
                self.prog.configure(mode="indeterminate")
                self.prog.start(10)
            else:
                self.prog.stop()
                self.prog.configure(mode="determinate")
                self.prog["value"] = max(0, min(100, int(pct)))

            # include error/skip counters
            region_count = getattr(self.state.bad_map, "region_count", lambda: 0)()
            paused_left = max(0.0, float(getattr(self.state, "pause_until", 0.0)) - time.time())
            paused_txt = f" | paused={paused_left:.1f}s" if paused_left > 0 else ""
            extra = (
                f" | bad_regions={region_count} | consec_err={self.state.consecutive_errors} | skip={self.state.skip_size}"
                f"{paused_txt}"
            )
            self.lbl_status.configure(text=f"{status}{extra}")
        except Exception:
            pass
        self.root.after(250, self._start_status_updater)

    def _start_ui_consumer(self) -> None:
        processed = 0
        try:
            while processed < 500:
                item = self.ui_queue.get_nowait()
                processed += 1
                if isinstance(item, Partition):
                    self._ui_add_partition(item)
                elif isinstance(item, _TreeItem):
                    self._ui_add_tree_item(item)
        except queue.Empty:
            pass
        self.root.after(50, self._start_ui_consumer)

    def action_stop(self) -> None:
        self.state.stop_requested = True
        self._log("CRITICAL", "Stop requested: aborting operations.")

    def action_browse_image(self) -> None:
        path = filedialog.askopenfilename()
        if not path:
            return
        self.entry_source.delete(0, tk.END)
        self.entry_source.insert(0, path)

    def action_browse_output(self) -> None:
        path = filedialog.askdirectory(title="Select output folder (different disk recommended)")
        if not path:
            return
        self.output_root = Path(path)
        self.entry_output.delete(0, tk.END)
        self.entry_output.insert(0, str(self.output_root))

    def action_open_logfile(self) -> None:
        # Best-effort open log in default app (read-only)
        try:
            import os
            import subprocess

            p = str(Path("pyddeu_debug.log").resolve())
            if IS_WINDOWS:
                os.startfile(p)  # type: ignore[attr-defined]
            else:
                subprocess.Popen(["xdg-open", p], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            return

    def action_list_disks(self) -> None:
        sources = list_sources()
        if not sources:
            messagebox.showinfo("Disks", "No disks found (or insufficient permissions).")
            return

        win = tk.Toplevel(self.root)
        win.title("Select Disk")
        win.geometry("700x400")

        lst = tk.Listbox(win, font=("Consolas", 10))
        lst.pack(fill=tk.BOTH, expand=True)

        for s in sources:
            gb = s.size / (1024**3) if s.size else 0
            lst.insert(tk.END, f"{s.path}  ({gb:.2f} GB)  {s.description}")

        def choose() -> None:
            sel = lst.curselection()
            if not sel:
                return
            val = lst.get(sel[0]).split("  ")[0]
            self.entry_source.delete(0, tk.END)
            self.entry_source.insert(0, val)
            win.destroy()

        ttk.Button(win, text="Use selected", command=choose).pack(pady=5)

    def action_connect(self) -> None:
        if _PYTSK3_IMPORT_ERROR is not None:
            messagebox.showerror(
                "pytsk3 missing",
                f"pytsk3 import failed: {_PYTSK3_IMPORT_ERROR}\n\nInstall requirements.txt first.",
            )
            return

        self.state.stop_requested = False
        self.state.is_alive = True

        path = self.entry_source.get().strip()
        if not path or path == format_source_hint():
            messagebox.showerror("Error", "Enter a disk/image path first.")
            return

        if IS_WINDOWS and path.startswith("/dev/"):
            messagebox.showerror(
                "Error", "This looks like a Linux device path. Use an image or \\\\.\\PhysicalDriveN."
            )
            return

        if (path.startswith("/dev/") or path.startswith(r"\\.\PhysicalDrive")) and not is_admin():
            messagebox.showwarning(
                "Permissions",
                "Raw device access requires Administrator/root.\nYou can still use an image file without admin.",
            )

        try:
            if self.source:
                self.source.close()
        except Exception:
            pass

        try:
            self.source = open_source(path)
            self.source_path = path
            size_gb = (self.source.size() or 0) / (1024**3)
            self._log("INFO", f"Connected: {path} ({size_gb:.2f} GB)")
            if self._monitor_thread is None:
                self._monitor_thread = start_monitor(self._log, self.source_path, state=self.state)
            # refresh output root from entry
            try:
                val = self.entry_output.get().strip()
                if val:
                    self.output_root = Path(val)
            except Exception:
                pass
        except OSError as e:
            self.source = None
            self._log("CRITICAL", f"Connect failed: {e}")
            messagebox.showerror("Connect failed", str(e))

    def action_scan_partitions(self) -> None:
        if not self.source:
            return
        self.state.stop_requested = False
        self.list_parts.delete(0, tk.END)
        self.partitions = []
        self._status_text = "Scanning partitions…"
        self._status_pct = None

        def worker() -> None:
            try:
                self.state.wait_if_paused()
                parts = scan_partitions(self.source, state=self.state, log_cb=self._log)
                if not parts:
                    self._log("WARNING", "No MBR/GPT partitions found. Trying read-only NTFS carve…")
                    total = self.source.size() or 0

                    def prog(off: int, total_size: int, hits: int) -> None:
                        if total_size > 0:
                            self._status_pct = int(min(99, (off / total_size) * 100))
                        self._status_text = f"Carving NTFS boots… hits={hits}"

                    parts = carve_ntfs_partitions(self.source, state=self.state, log_cb=self._log, progress_cb=prog)
                    if not parts:
                        self._log("WARNING", "No carved NTFS boot sectors found.")
                for p in parts:
                    self.partitions.append(p)
                    self.ui_queue.put(p)
                self._log("INFO", f"Partitions: {len(parts)}")
                self._status_text = "Partition scan done"
                self._status_pct = 100
            except Exception as e:
                self._log("CRITICAL", f"Partition scan failed: {e}")
                self._status_text = "Partition scan failed"
                self._status_pct = None

        threading.Thread(target=worker, daemon=True).start()

    def _ui_add_partition(self, p: Partition) -> None:
        gb = p.length / (1024**3)
        label = f"[{p.index}] {p.scheme} {p.type_str} start={p.start_offset} size={gb:.2f}GB"
        if p.name:
            label += f" name={p.name}"
        self.list_parts.insert(tk.END, label)

    def on_partition_select(self, _event: object) -> None:
        sel = self.list_parts.curselection()
        if not sel or not self.source:
            return
        idx = sel[0]
        if idx >= len(self.partitions):
            return
        part = self.partitions[idx]
        try:
            from .scan import safe_read_granular

            data = safe_read_granular(self.source, self.state, part.start_offset, 512, log_cb=self._log)
            display_text = f"Offset: {part.start_offset} (Boot Sector)\n" + "-" * 60 + "\n"
            for i in range(0, len(data), 16):
                chunk = data[i : i + 16]
                hex_part = " ".join(f"{b:02X}" for b in chunk)
                ascii_part = "".join((chr(b) if 32 <= b < 127 else ".") for b in chunk)
                display_text += f"{i:04X}  {hex_part:<48}  |{ascii_part}|\n"
            self.txt_hex.delete(1.0, tk.END)
            self.txt_hex.insert(tk.END, display_text)
        except Exception as e:
            self._log("WARNING", f"Hex view failed: {e}")

    def action_parse_fs(self) -> None:
        if not self.source:
            return
        sel = self.list_parts.curselection()
        if not sel:
            messagebox.showwarning("Select partition", "Pick a partition first.")
            return
        idx = sel[0]
        if idx >= len(self.partitions):
            return
        part = self.partitions[idx]

        self.tree.delete(*self.tree.get_children())
        self.node_metadata = {}
        self.state.stop_requested = False

        def log_cb(level: str, msg: str) -> None:
            self._log(level, msg)

        def worker() -> None:
            try:
                self._status_text = "Parsing NTFS via pytsk3…"
                self._status_pct = None
                src = open_source(self.source_path)
                img = DDEUImg(src, self.state, log_cb=log_cb)
                fs = pytsk3.FS_Info(img, offset=part.start_offset)
                root_dir = fs.open_dir(path="/")
                self._walk_dir(root_dir, "", part.start_offset)
                src.close()
                self._log("INFO", "NTFS parse completed.")
                self._status_text = "NTFS parse done"
                self._status_pct = 100
            except Exception as e:
                self._log("CRITICAL", f"NTFS parse failed: {e}")
                self._status_text = "NTFS parse failed"
                self._status_pct = None

        threading.Thread(target=worker, daemon=True).start()

    def action_deep_ntfs_scan(self) -> None:
        if not self.source:
            return
        sel = self.list_parts.curselection()
        if not sel:
            messagebox.showwarning("Select partition", "Pick a partition first.")
            return
        idx = sel[0]
        if idx >= len(self.partitions):
            return
        part = self.partitions[idx]

        self.state.stop_requested = False
        self.tree.delete(*self.tree.get_children())
        self.node_metadata = {}
        self._resident_cache = {}
        self._nonresident_cache = {}

        def log_cb(level: str, msg: str) -> None:
            self._log(level, msg)

        def worker() -> None:
            try:
                self._status_text = "Deep NTFS scan (MFT)…"
                self._status_pct = 0
                src = open_source(self.source_path)
                boot_buf = src.read_at(part.start_offset, 512)
                boot = parse_ntfs_boot_sector(boot_buf)
                if not boot:
                    self._log("CRITICAL", "Selected partition does not look like NTFS boot sector.")
                    src.close()
                    self._status_text = "Deep scan failed"
                    self._status_pct = None
                    return

                cluster_size = boot.cluster_size
                self._log("INFO", f"NTFS boot parsed: cluster={cluster_size} record={boot.file_record_size}")

                def progress(off: int, total: int) -> None:
                    if total > 0:
                        self._status_pct = int(min(99, (off / total) * 100))

                collected = []
                for rec in scan_and_parse_mft(
                    src,
                    self.state,
                    start=part.start_offset,
                    end=part.start_offset + boot.volume_size_bytes,
                    step=4096,
                    record_size=boot.file_record_size,
                    log_cb=log_cb,
                    progress_cb=progress,
                ):
                    if self.state.stop_requested:
                        break
                    collected.append(rec)
                    if len(collected) % 500 == 0:
                        self._log("INFO", f"Deep scan parsed records: {len(collected)}")

                paths = build_paths(collected)
                for rec in collected:
                    status = "DELETED" if rec.is_deleted else "ACTIVE"
                    size = rec.data_size or (len(rec.resident_data) if rec.resident_data else 0)
                    self.ui_queue.put(
                        _TreeItem(
                            path=f"[DEEP] {paths.get(rec.inode, f'inode_{rec.inode}')}",
                            size=int(size),
                            status=status,
                            inode=rec.inode,
                            part_offset=part.start_offset,
                            is_dir=False,
                            resident_data=rec.resident_data,
                            data_runs=rec.data_runs,
                            data_size=rec.data_size,
                            cluster_size=cluster_size,
                        )
                    )

                src.close()
                self._status_text = "Deep scan done"
                self._status_pct = 100
                self._log("INFO", f"Deep scan finished. Records: {len(collected)}")
            except Exception as e:
                self._log("CRITICAL", f"Deep scan failed: {e}")
                self._status_text = "Deep scan failed"
                self._status_pct = None

        threading.Thread(target=worker, daemon=True).start()

    def action_mft_scan(self) -> None:
        if not self.source:
            return
        self.state.stop_requested = False
        self.tree.delete(*self.tree.get_children())
        self.node_metadata = {}
        self._resident_cache = {}

        def log_cb(level: str, msg: str) -> None:
            self._log(level, msg)

        def worker() -> None:
            self._log("INFO", "Starting raw MFT scan (signature FILE)…")
            try:
                self._status_text = "MFT scan (RAW)…"
                self._status_pct = 0
                src = open_source(self.source_path)
                count = 0
                collected = []
                total = src.size() or 0
                def progress(off: int, total: int) -> None:
                    if total > 0:
                        self._status_pct = int(min(99, (off / total) * 100))

                for rec in scan_and_parse_mft(
                    src, self.state, step=4096, record_size=1024, log_cb=log_cb, progress_cb=progress
                ):
                    if self.state.stop_requested:
                        break
                    collected.append(rec)
                    count += 1
                    if count % 200 == 0:
                        self._log("INFO", f"MFT candidates parsed: {count}")
                paths = build_paths(collected)
                for rec in collected:
                    status = "DELETED" if rec.is_deleted else "ACTIVE"
                    size = len(rec.resident_data) if rec.resident_data is not None else 0
                    self.ui_queue.put(
                        _TreeItem(
                            path=f"[MFT] {paths.get(rec.inode, f'inode_{rec.inode}')}",
                            size=size,
                            status=status,
                            inode=rec.inode,
                            part_offset=0,
                            is_dir=False,
                            resident_data=rec.resident_data,
                        )
                    )
                src.close()
                self._log("INFO", f"MFT scan finished. Parsed: {count}")
                self._status_text = "MFT scan done"
                self._status_pct = 100
            except Exception as e:
                self._log("CRITICAL", f"MFT scan failed: {e}")
                self._status_text = "MFT scan failed"
                self._status_pct = None

        threading.Thread(target=worker, daemon=True).start()

    def action_file_carve(self) -> None:
        if not self.source:
            return
        out_dir = filedialog.askdirectory(title="Select output folder for carved files")
        if not out_dir:
            return
        self.state.stop_requested = False

        def log_cb(level: str, msg: str) -> None:
            self._log(level, msg)

        def worker() -> None:
            try:
                src = open_source(self.source_path)
                self._log("INFO", f"Starting RAW file carving to: {out_dir}")
                self._status_text = "RAW file carve…"
                self._status_pct = 0
                def progress2(off: int, total: int) -> None:
                    if total > 0:
                        self._status_pct = int(min(99, (off / total) * 100))

                found = carve_signatures(src, self.state, Path(out_dir), log_cb=log_cb, progress_cb=progress2)
                src.close()
                self._log("INFO", f"RAW carving finished. Found: {found}")
                self._status_text = "RAW carve done"
                self._status_pct = 100
            except Exception as e:
                self._log("CRITICAL", f"RAW carving failed: {e}")
                self._status_text = "RAW carve failed"
                self._status_pct = None

        threading.Thread(target=worker, daemon=True).start()

    def _walk_dir(self, directory: "pytsk3.Directory", base: str, part_offset: int) -> None:
        if self.state.stop_requested:
            return
        for entry in directory:
            if self.state.stop_requested:
                return
            try:
                if not hasattr(entry.info, "name") or not entry.info.name:
                    continue
                name_bytes = entry.info.name.name
                if not name_bytes:
                    continue
                name = name_bytes.decode("utf-8", errors="replace")
                if name in (".", "..", "$MFT", "$LogFile", "$BadClus"):
                    continue
                meta = entry.info.meta
                if not meta:
                    continue
                status = "DELETED" if (meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC) else "ACTIVE"
                full_path = f"{base}/{name}" if base else name
                inode = int(meta.addr)
                is_dir = meta.type == pytsk3.TSK_FS_META_TYPE_DIR
                size = int(meta.size or 0)
                self.ui_queue.put(
                    _TreeItem(
                        path=full_path,
                        size=size,
                        status=status,
                        inode=inode,
                        part_offset=part_offset,
                        is_dir=is_dir,
                    )
                )
                if is_dir:
                    self._walk_dir(entry.as_directory(), full_path, part_offset)
            except Exception:
                continue

    def _ui_add_tree_item(self, item: _TreeItem) -> None:
        node_id = self.tree.insert("", "end", text=item.path, values=(item.size, item.status, item.inode))
        self.node_metadata[node_id] = (item.part_offset, item.inode, item.is_dir)
        if item.resident_data:
            self._resident_cache[node_id] = item.resident_data
        if item.data_runs and item.cluster_size:
            self._nonresident_cache[node_id] = (
                int(item.part_offset),
                int(item.cluster_size),
                list(item.data_runs),
                int(item.data_size) if item.data_size is not None else None,
            )

    def show_context_menu(self, event: tk.Event) -> None:
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def recover_selected_file(self) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        node_id = sel[0]
        meta = self.node_metadata.get(node_id)
        if not meta:
            return
        part_offset, inode, is_dir = meta
        if is_dir:
            messagebox.showerror("Recover", "Selected item is a directory.")
            return

        # Use global output root, preserve relative path where possible.
        try:
            self.output_root = Path(self.entry_output.get().strip())
        except Exception:
            pass
        if not self.output_root:
            chosen = filedialog.askdirectory(title="Select output folder (different disk recommended)")
            if not chosen:
                return
            self.output_root = Path(chosen)
            self.entry_output.delete(0, tk.END)
            self.entry_output.insert(0, str(self.output_root))

        item_text = self.tree.item(node_id, "text")
        rel = _normalize_rel_path(item_text)
        if not rel:
            rel = f"inode_{inode}"
        target_path = str((self.output_root / rel).resolve())

        resident = self._resident_cache.get(node_id)
        if resident is not None:
            try:
                Path(target_path).parent.mkdir(parents=True, exist_ok=True)
                with open(target_path, "wb") as f:
                    f.write(resident)
                self._log("INFO", f"Saved resident data: {target_path}")
            except Exception as e:
                self._log("CRITICAL", f"Resident save failed: {e}")
            return

        nonres = self._nonresident_cache.get(node_id)
        if nonres is not None:
            part_off, cluster_size, runs, expected = nonres
            try:
                src = open_source(self.source_path)
                recover_nonresident_runs(
                    src,
                    self.state,
                    Path(target_path),
                    part_offset=part_off,
                    cluster_size=cluster_size,
                    runs=runs,
                    expected_size=expected,
                    log_cb=self._log,
                )
                src.close()
                self._log("INFO", f"Saved non-resident data: {target_path}")
            except Exception as e:
                self._log("CRITICAL", f"Non-resident recover failed: {e}")
            return

        # Fallback: pytsk3-based recovery for normal NTFS parse tree items
        if self.source_path and part_offset:
            def log_cb(level: str, msg: str) -> None:
                self._log(level, msg)

            def worker() -> None:
                self._log("INFO", f"Recovering via pytsk3 -> {target_path}")
                try:
                    src = open_source(self.source_path)
                    img = DDEUImg(src, self.state, log_cb=log_cb)
                    fs = pytsk3.FS_Info(img, offset=part_offset)
                    exporter = RobustExporter(fs, self.state, log_cb=self._log)

                    def progress(file_off: int, file_size: int) -> None:
                        self._status_text = f"Recovering (robust): {Path(target_path).name}"
                        if file_size > 0:
                            self._status_pct = int(min(99, (file_off / file_size) * 100))
                        else:
                            self._status_pct = None

                    exporter.export_inode(inode, Path(target_path), progress_cb=progress)
                    src.close()
                    self._log("INFO", f"Saved: {target_path}")
                    self._status_text = "Recover done"
                    self._status_pct = 100
                except Exception as e:
                    self._log("CRITICAL", f"Recover failed: {e}")
                    self._status_text = "Recover failed"
                    self._status_pct = None

            threading.Thread(target=worker, daemon=True).start()
            return

    def action_create_image(self) -> None:
        if not self.source:
            return
        out_path = filedialog.asksaveasfilename(
            title="Save image as",
            defaultextension=".img",
            filetypes=[("Raw image", "*.img *.dd *.bin"), ("All files", "*.*")],
        )
        if not out_path:
            return
        self.state.stop_requested = False

        def log_cb(level: str, msg: str) -> None:
            self._log(level, msg)

        def progress(off: int, total: int) -> None:
            if total > 0:
                self._status_pct = int(min(99, (off / total) * 100))

        def worker() -> None:
            try:
                self._status_text = "Imaging…"
                self._status_pct = 0
                src = open_source(self.source_path)
                self._log("INFO", f"Imaging started -> {out_path}")
                create_image(src, self.state, Path(out_path), log_cb=log_cb, progress_cb=progress)
                src.close()
                self._log("INFO", f"Imaging finished -> {out_path}")
                self._status_text = "Imaging done"
                self._status_pct = 100
            except Exception as e:
                self._log("CRITICAL", f"Imaging failed: {e}")
                self._status_text = "Imaging failed"
                self._status_pct = None

        threading.Thread(target=worker, daemon=True).start()

    def action_image_selected_partition(self) -> None:
        if not self.source:
            return
        sel = self.list_parts.curselection()
        if not sel:
            messagebox.showwarning("Select partition", "Pick a partition first.")
            return
        idx = sel[0]
        if idx >= len(self.partitions):
            return
        part = self.partitions[idx]
        out_path = filedialog.asksaveasfilename(
            title="Save partition image as",
            defaultextension=".img",
            filetypes=[("Raw image", "*.img *.dd *.bin"), ("All files", "*.*")],
        )
        if not out_path:
            return
        if part.length <= 0:
            messagebox.showerror("Image", "Partition size is unknown; use full-disk imaging instead.")
            return
        self.state.stop_requested = False

        def progress(off: int, total: int) -> None:
            if total > 0:
                self._status_pct = int(min(99, (off / total) * 100))

        def worker() -> None:
            try:
                self._status_text = "Imaging partition…"
                self._status_pct = 0
                src = open_source(self.source_path)
                start = int(part.start_offset)
                end = int(part.start_offset + part.length)
                self._log("INFO", f"Partition imaging started [{start}..{end}) -> {out_path}")
                create_image(
                    src,
                    self.state,
                    Path(out_path),
                    start=start,
                    end=end,
                    log_cb=self._log,
                    progress_cb=progress,
                )
                src.close()
                self._log("INFO", f"Partition imaging finished -> {out_path}")
                self._status_text = "Partition imaging done"
                self._status_pct = 100
            except Exception as e:
                self._log("CRITICAL", f"Partition imaging failed: {e}")
                self._status_text = "Partition imaging failed"
                self._status_pct = None

        threading.Thread(target=worker, daemon=True).start()

    def action_export_all(self) -> None:
        if not self.source:
            return
        try:
            self.output_root = Path(self.entry_output.get().strip())
        except Exception:
            pass
        if not self.output_root:
            messagebox.showerror("Export", "Select an output folder first.")
            return

        ext_set = _parse_ext_filter(self.entry_ext.get())
        max_bytes = _parse_max_mb(self.entry_max_mb.get())
        skip_archives = bool(self.var_skip_archives.get())
        skip_existing = bool(self.var_skip_existing.get())
        include_deleted = bool(self.var_export_deleted.get())
        include_active = bool(self.var_export_active.get())
        if not include_deleted and not include_active:
            messagebox.showwarning("Export", "Select at least one of Deleted/Active.")
            return

        items = list(self.tree.get_children(""))
        if not items:
            messagebox.showinfo("Export", "No items to export (list is empty).")
            return

        self.state.stop_requested = False
        self._status_text = "Exporting…"
        self._status_pct = 0

        def worker() -> None:
            exported = 0
            skipped = 0
            total = len(items)
            src = None
            try:
                src = self.source
                if src is None:
                    raise RuntimeError("Disk not connected.")
                img = DDEUImg(src, self.state, log_cb=self._log)
                exporter_cache: dict[int, RobustExporter] = {}

                for idx, node_id in enumerate(items, start=1):
                    if self.state.stop_requested or not self.state.is_alive:
                        break
                    try:
                        part_offset, inode, is_dir = self.node_metadata.get(node_id, (0, 0, False))
                        if is_dir:
                            skipped += 1
                            continue
                        status = str(self.tree.set(node_id, "status") or "")
                        if status == "DELETED" and not include_deleted:
                            skipped += 1
                            continue
                        if status == "ACTIVE" and not include_active:
                            skipped += 1
                            continue

                        item_text = self.tree.item(node_id, "text")
                        rel = _normalize_rel_path(item_text) or f"inode_{inode}"
                        file_size = _get_tree_size(self.tree, node_id)
                        if max_bytes > 0 and file_size > max_bytes:
                            skipped += 1
                            self._log("INFO", f"Skipped (too large): {rel} ({file_size} B)")
                            continue
                        if skip_archives and _is_archive_path(rel):
                            skipped += 1
                            self._log("INFO", f"Skipped (archive): {rel} ({file_size} B)")
                            continue
                        if ext_set and not _ext_allowed(rel, ext_set):
                            skipped += 1
                            continue
                        target = (self.output_root / rel)
                        if skip_existing and _should_skip_existing(target, file_size):
                            skipped += 1
                            continue
                        if not skip_existing:
                            target = self._unique_path(target)

                        # Prefer cached deep-scan recoveries
                        resident = self._resident_cache.get(node_id)
                        if resident is not None:
                            target.parent.mkdir(parents=True, exist_ok=True)
                            target.write_bytes(resident)
                            exported += 1
                            self._log("INFO", f"Exported (resident): {target}")
                        else:
                            nonres = self._nonresident_cache.get(node_id)
                            if nonres is not None:
                                part_off2, cluster_size, runs, expected = nonres
                                recover_nonresident_runs(
                                    src,
                                    self.state,
                                    target,
                                    part_offset=part_off2,
                                    cluster_size=cluster_size,
                                    runs=runs,
                                    expected_size=expected,
                                    log_cb=self._log,
                                )
                                exported += 1
                                self._log("INFO", f"Exported (non-resident): {target}")
                            else:
                                exporter = exporter_cache.get(int(part_offset))
                                if exporter is None:
                                    fs = pytsk3.FS_Info(img, offset=int(part_offset))
                                    exporter = RobustExporter(fs, self.state, log_cb=self._log)
                                    exporter_cache[int(part_offset)] = exporter

                                def progress(file_off: int, file_size2: int) -> None:
                                    base = idx - 1
                                    frac = (file_off / file_size2) if file_size2 > 0 else 0.0
                                    self._status_pct = int(min(99, ((base + frac) / total) * 100))

                            ok = exporter.export_inode(inode, target, progress_cb=progress)
                            if ok:
                                exported += 1
                                self._log("INFO", f"Exported: {target}")
                            else:
                                skipped += 1
                    except Exception as e:
                        skipped += 1
                        self._log("WARNING", f"Export skipped ({node_id}): {e}")

                    self._status_pct = int((idx / total) * 100)
                    self._status_text = f"Exporting… {idx}/{total} (ok={exported} skip={skipped})"
            finally:
                pass

            self._status_text = f"Export done (ok={exported} skip={skipped})"
            self._status_pct = 100

        threading.Thread(target=worker, daemon=True).start()

    def action_recover_all(self) -> None:
        """
        Bulk recovery using robust, zero-fill export for every listed file.

        Unlike Export All, this ignores Deleted/Active filters.
        """
        if not self.source:
            return
        try:
            self.output_root = Path(self.entry_output.get().strip())
        except Exception:
            pass
        if not self.output_root:
            messagebox.showerror("Recover", "Select an output folder first.")
            return

        items = list(self.tree.get_children(""))
        if not items:
            messagebox.showinfo("Recover", "No items to recover (list is empty).")
            return

        self.state.stop_requested = False
        self._status_text = "Recovering (robust)."
        self._status_pct = 0

        def worker() -> None:
            ok_count = 0
            skipped = 0
            total = len(items)
            max_bytes = _parse_max_mb(self.entry_max_mb.get())
            skip_archives = bool(self.var_skip_archives.get())
            skip_existing = bool(self.var_skip_existing.get())
            ext_set = _parse_ext_filter(self.entry_ext.get())
            src = None
            try:
                src = self.source
                if src is None:
                    raise RuntimeError("Disk not connected.")
                img = DDEUImg(src, self.state, log_cb=self._log)
                exporter_cache: dict[int, RobustExporter] = {}

                for idx, node_id in enumerate(items, start=1):
                    if self.state.stop_requested or not self.state.is_alive:
                        break
                    try:
                        part_offset, inode, is_dir = self.node_metadata.get(node_id, (0, 0, False))
                        if is_dir:
                            skipped += 1
                            continue

                        item_text = self.tree.item(node_id, "text")
                        rel = _normalize_rel_path(item_text) or f"inode_{inode}"
                        file_size = _get_tree_size(self.tree, node_id)
                        if max_bytes > 0 and file_size > max_bytes:
                            skipped += 1
                            self._log("INFO", f"Skipped (too large): {rel} ({file_size} B)")
                            continue
                        if skip_archives and _is_archive_path(rel):
                            skipped += 1
                            self._log("INFO", f"Skipped (archive): {rel} ({file_size} B)")
                            continue
                        if ext_set and not _ext_allowed(rel, ext_set):
                            skipped += 1
                            continue
                        target = (self.output_root / rel)
                        if skip_existing and _should_skip_existing(target, file_size):
                            skipped += 1
                            continue
                        if not skip_existing:
                            target = self._unique_path(target)

                        resident = self._resident_cache.get(node_id)
                        if resident is not None:
                            target.parent.mkdir(parents=True, exist_ok=True)
                            target.write_bytes(resident)
                            ok_count += 1
                            self._log("INFO", f"Recovered (resident): {target}")
                        else:
                            nonres = self._nonresident_cache.get(node_id)
                            if nonres is not None:
                                part_off2, cluster_size, runs, expected = nonres
                                recover_nonresident_runs(
                                    src,
                                    self.state,
                                    target,
                                    part_offset=part_off2,
                                    cluster_size=cluster_size,
                                    runs=runs,
                                    expected_size=expected,
                                    log_cb=self._log,
                                )
                                ok_count += 1
                                self._log("INFO", f"Recovered (non-resident): {target}")
                            else:
                                exporter = exporter_cache.get(int(part_offset))
                                if exporter is None:
                                    fs = pytsk3.FS_Info(img, offset=int(part_offset))
                                    exporter = RobustExporter(fs, self.state, log_cb=self._log)
                                    exporter_cache[int(part_offset)] = exporter

                                def progress(file_off: int, file_size2: int) -> None:
                                    base = idx - 1
                                    frac = (file_off / file_size2) if file_size2 > 0 else 0.0
                                    self._status_pct = int(min(99, ((base + frac) / total) * 100))
                                    self._status_text = (
                                        f"Recovering (robust). {idx}/{total} (ok={ok_count} skip={skipped})"
                                    )

                                ok = exporter.export_inode(inode, target, progress_cb=progress)
                                if ok:
                                    ok_count += 1
                                    self._log("INFO", f"Recovered: {target}")
                                else:
                                    skipped += 1
                    except Exception as e:
                        skipped += 1
                        self._log("WARNING", f"Recover skipped ({node_id}): {e}")

                    self._status_pct = int((idx / total) * 100)
                    self._status_text = f"Recovering (robust). {idx}/{total} (ok={ok_count} skip={skipped})"
            finally:
                pass

            self._status_text = f"Recover done (ok={ok_count} skip={skipped})"
            self._status_pct = 100

        threading.Thread(target=worker, daemon=True).start()

    def action_recover_all_mft(self) -> None:
        """
        MFT Analizi sonucu bulunan dosyaları, klasör yapısını koruyarak dışarı aktarır.
        Sadece listedeki (parsed) dosyaları hedef alır, raw carving yapmaz.
        """
        if not self.source:
            return

        # Eğer liste boşsa uyar
        if not self.tree.get_children():
            messagebox.showwarning("Uyarı", "Liste boş. Önce 'Parse NTFS' veya 'Deep Scan' yapın.")
            return

        # Export/Recover ile tutarli olmasi icin once Output alanini kullan.
        try:
            out_txt = self.entry_output.get().strip()
            target_root = Path(out_txt) if out_txt else None
        except Exception:
            target_root = None
        if not target_root:
            picked = filedialog.askdirectory(title="Kurtarılan Dosyalar Nereye Kaydedilsin?")
            if not picked:
                return
            target_root = Path(picked)

        self.state.stop_requested = False
        threading.Thread(target=self._thread_recover_all_mft, args=(Path(target_root),), daemon=True).start()

    def _thread_recover_all_mft(self, target_root: Path) -> None:

        self._log("INFO", "=== TOPLU KURTARMA (AKILLI MOD) BASLATILDI ===")

        skip_existing = bool(self.var_skip_existing.get())
        skip_archives = bool(self.var_skip_archives.get())
        ext_set = _parse_ext_filter(self.entry_ext.get())

        max_bytes_ui = _parse_max_mb(self.entry_max_mb.get())
        max_file_size = max_bytes_ui if max_bytes_ui > 0 else 100 * 1024 * 1024
        retry_limit = 3

        items = list(self.tree.get_children(""))
        total = len(items)
        exported = 0
        skipped = 0
        errors = 0

        def looks_like_device_reset(err: BaseException) -> bool:
            msg = str(err).lower()
            needles = (
                "reset to device",
                "device was reset",
                "i/o device error",
                "io device error",
                "input/output error",
                "semaphore timeout",
                "the device is not ready",
                "invalid handle",
                "handle is invalid",
                "errno 22",
                "parameter is incorrect",
                "winerror 6",
                "winerror 87",
                "winerror 1117",
            )
            return any(n in msg for n in needles)

        def connect_img():
            try:
                s = open_source(self.source_path)
                i = DDEUImg(s, self.state, log_cb=self._log)
                return s, i
            except Exception as e:
                self._log("CRITICAL", f"Disk baglantisi kurulamadi: {e}")
                return None, None

        def connect_fs(img_obj: object, offset: int):
            try:
                return pytsk3.FS_Info(img_obj, offset=int(offset))
            except Exception as e:
                self._log("CRITICAL", f"FS acilamadi (offset={offset}): {e}")
                return None

        if not self.node_metadata:
            self._log("WARNING", "Kurtarilacak dosya listesi yok.")
            return

        src = None
        img = None
        fs = None
        current_fs_offset: int | None = None

        try:
            for idx, node_id in enumerate(items, start=1):
                if self.state.stop_requested or not self.state.is_alive:
                    self._log("WARNING", "Islem durduruldu.")
                    break

                meta = self.node_metadata.get(node_id)
                if not meta:
                    skipped += 1
                    continue

                part_offset, inode, is_dir = meta
                part_offset = int(part_offset)
                inode = int(inode)

                if is_dir:
                    skipped += 1
                    continue

                item_text = self.tree.item(node_id, "text")
                rel_path = _normalize_rel_path(item_text) or f"inode_{inode}"
                file_size = _get_tree_size(self.tree, node_id)

                if ext_set and not _ext_allowed(rel_path, ext_set):
                    skipped += 1
                    continue
                if skip_archives and _is_archive_path(rel_path):
                    skipped += 1
                    continue

                out_path = target_root / rel_path
                if skip_existing:
                    if _should_skip_existing(out_path, file_size):
                        skipped += 1
                        continue
                else:
                    if out_path.exists():
                        out_path = self._unique_path(out_path)

                if max_file_size > 0 and file_size > max_file_size:
                    self._log("WARNING", f"Buyuk dosya atlandi (>{max_file_size // (1024 * 1024)}MB): {rel_path}")
                    try:
                        out_path.parent.mkdir(parents=True, exist_ok=True)
                        with open(str(out_path) + ".skipped", "w", encoding="utf-8") as f:
                            f.write(f"Skipped due to size: {file_size}")
                    except Exception:
                        pass
                    skipped += 1
                    continue

                self._status_text = f"Recovering (MFT): {rel_path} ({idx}/{total})"
                self._status_pct = int((idx / total) * 100) if total > 0 else 0

                retry_count = 0
                success = False
                while retry_count < retry_limit and not self.state.stop_requested and self.state.is_alive:
                    if src is None or img is None:
                        self._log("INFO", "Disk baglantisi yenileniyor...")
                        time.sleep(5)
                        src, img = connect_img()
                        fs = None
                        current_fs_offset = None
                        if src is None or img is None:
                            self._log("CRITICAL", "Disk baglantisi basarisiz. Tekrar deneniyor...")
                            time.sleep(10)
                            retry_count += 1
                            continue

                    if fs is None or current_fs_offset != part_offset:
                        fs = connect_fs(img, part_offset)
                        current_fs_offset = part_offset if fs is not None else None
                        if fs is None:
                            retry_count += 1
                            time.sleep(5)
                            continue

                    try:
                        exporter = RobustExporter(fs, self.state, log_cb=None)
                        ok = exporter.export_inode(inode, out_path)
                        if ok:
                            exported += 1
                            success = True
                            break
                        raise OSError("Export returned false")
                    except Exception as e:
                        retry_count += 1
                        if looks_like_device_reset(e):
                            self._log(
                                "CRITICAL",
                                f"Dosya hatasi ({retry_count}/{retry_limit}): {rel_path} -> {e}",
                            )
                            self._log("INFO", "Disk reset yemis olabilir. Baglanti kapatiliyor...")
                            try:
                                if src is not None:
                                    src.close()
                            except Exception:
                                pass
                            src, img, fs = None, None, None
                            current_fs_offset = None
                            time.sleep(10)
                        else:
                            self._log("WARNING", f"Hata ({retry_count}/{retry_limit}): {rel_path} -> {e}")
                            time.sleep(1)

                if not success:
                    errors += 1
                    self._log("ERROR", f"Dosya kurtarilamadi: {rel_path}")
        except Exception as e:
            self._log("CRITICAL", f"Ana dongu hatasi: {e}")
        finally:
            try:
                if src is not None:
                    src.close()
            except Exception:
                pass
            self._log("INFO", f"=== ISLEM BITTI === Basarili: {exported}, Atlanan: {skipped}, Hatali: {errors}")
            self._status_text = "Recovery Completed"
            self._status_pct = 100

    def _unique_path(self, path: Path) -> Path:
        """
        Avoid overwriting: if a file already exists, append _N before extension.
        """
        p = path
        if not p.exists():
            return p
        stem = p.stem
        suf = p.suffix
        parent = p.parent
        i = 1
        while True:
            cand = parent / f"{stem}_{i}{suf}"
            if not cand.exists():
                return cand
            i += 1


def _normalize_rel_path(item_text: str) -> str:
    """
    Convert UI tree text into a safe relative path under output_root.
    """
    t = item_text.strip()
    for prefix in ("[DEEP]", "[MFT]", "[DEEP] ", "[MFT] ", "[DEEP]  ", "[MFT]  "):
        if t.startswith(prefix):
            t = t[len(prefix) :].strip()
    t = t.replace("\\", "/").lstrip("/")
    # Prevent path traversal
    parts = []
    for p in t.split("/"):
        p = p.strip().strip(".")
        if not p or p in (".", ".."):
            continue
        # Windows-invalid chars
        for ch in '<>:"|?*':
            p = p.replace(ch, "_")
        parts.append(p)
    return "/".join(parts)


def _parse_ext_filter(raw: str) -> set[str]:
    exts = set()
    for part in (raw or "").split(","):
        p = part.strip().lower().lstrip(".")
        if p:
            exts.add(p)
    return exts


def _ext_allowed(rel: str, exts: set[str]) -> bool:
    name = Path(rel).name.lower()
    if "." not in name:
        return False
    return name.rsplit(".", 1)[-1] in exts


def _parse_max_mb(raw: str) -> int:
    try:
        mb = int((raw or "").strip() or "0")
    except Exception:
        mb = 0
    if mb <= 0:
        return 0
    return mb * 1024 * 1024


def _get_tree_size(tree: ttk.Treeview, node_id: str) -> int:
    try:
        v = tree.set(node_id, "size")
        return int(v) if v is not None and str(v).strip() else 0
    except Exception:
        return 0


_ARCHIVE_EXTS = {
    "zip",
    "rar",
    "7z",
    "tar",
    "gz",
    "bz2",
    "xz",
    "tgz",
    "tbz",
    "tbz2",
    "txz",
    "iso",
    "cab",
}


def _is_archive_path(rel: str) -> bool:
    name = Path(rel).name.lower()
    if "." not in name:
        return False
    return name.rsplit(".", 1)[-1] in _ARCHIVE_EXTS


def _should_skip_existing(path: Path, expected_size: int) -> bool:
    """
    Skip only when we are confident the file is already recovered.
    - If expected_size known (>0): skip when sizes match.
    - If unknown: skip when destination is non-empty.
    """
    try:
        if not path.exists():
            return False
        try:
            st = path.stat()
        except Exception:
            return True
        existing = int(getattr(st, "st_size", 0) or 0)
        if expected_size and expected_size > 0:
            return existing == int(expected_size)
        return existing > 0
    except Exception:
        return False


def _default_output_root() -> Path:
    home = Path.home()
    if IS_WINDOWS:
        desktop = home / "Desktop"
        if desktop.exists():
            return desktop / "recovered"
    return home / "recovered"


def main() -> None:
    root = tk.Tk()
    PyDDEUGui(root)
    root.mainloop()
