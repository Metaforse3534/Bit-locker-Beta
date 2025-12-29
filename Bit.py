#Made By Joost Boerefijn

import ctypes
import subprocess
import sys
import time
import re
from pathlib import Path
from datetime import datetime, timedelta
import platform
import threading
import queue
import hmac
import hashlib
import base64
import json
import secrets
import os
import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk, messagebox, filedialog, simpledialog

# Optional Pillow support for nicer icon resizing
try:
    from PIL import Image, ImageTk
    _HAS_PIL = True
except Exception:
    _HAS_PIL = False

LOG_FILE = Path(__file__).with_suffix('.log')
CHECK_INTERVAL = 15  # seconden
BACKUP_DIR = Path(__file__).parent / "bitlocker_backups"

COMPANY_NAME = "MenthaForce Coperation"
PRODUCT_NAME = "MenthaForce BitLocker Manager"
VERSION = "0.1.0"

LICENSE_FILE = Path(__file__).with_suffix('.lic')
TRIAL_DAYS = 7
# NOTE: For production, use server-side signing. This local secret is only for demo/test purposes.
LOCAL_LICENSE_SECRET = b"change-me-to-a-secure-secret"  # replace before production

# Embedded default app icon (PNG, base64 encoded). Replace with your own icon.png or icon.ico in the app folder.
ICON_PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABAQMAAAAl21bKAAAACVBMVEUAAAD///+l2Z/dAAAACklEQVQI12NgAAAAAgAB4iG8MwAAAABJRU5ErkJggg=="
)

# Embedded logos (small placeholders). Replace with your real base64 PNGs for better visuals.
LOGO_PNG_B64_LIGHT = (
    "iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAQAAAAAYLlVAAAAJ0lEQVR4Ae3BMQEAAADCoPdPbQ43oAAAAAAAAAAAAAAAAAAAAAAA4G4G2wAAB5x0JbgAAAABJRU5ErkJggg=="
)
LOGO_PNG_B64_DARK = (
    "iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAQAAAAAYLlVAAAAJ0lEQVR4Ae3BMQEAAADCoPdPbQ43oAAAAAAAAAAAAAAAAAAAAAAA4G4G2wAAB5x0JbgAAAABJRU5ErkJggg=="
)

# Windows AppUserModelID so the taskbar groups and icon show the app icon instead of the Python icon
APP_ID = "MenthaForce.BitLocker.1"


# ---------- Utilities ----------

def log(msg: str) -> None:
    timestamp = datetime.now().isoformat(sep=' ', timespec='seconds')
    entry = f"[{timestamp}] {msg}"
    print(entry)
    try:
        with LOG_FILE.open('a', encoding='utf-8') as f:
            f.write(entry + '\n')
    except Exception:
        pass


def is_windows() -> bool:
    return platform.system() == 'Windows'


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()  # type: ignore
    except Exception:
        return False


def run_cmd(cmd: list[str]) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True)
        out = p.stdout + p.stderr
        return p.returncode, out
    except FileNotFoundError:
        return 127, f"Command not found: {cmd[0]}"


# ---------- Licensing helpers ----------

def _hmac_for_payload(payload: bytes) -> str:
    return hmac.new(LOCAL_LICENSE_SECRET, payload, hashlib.sha256).hexdigest()


def validate_license_content(content: str) -> bool:
    try:
        sig, payload = content.split(':', 1)
        expected = hmac.new(LOCAL_LICENSE_SECRET, payload.encode('utf-8'), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return False
        m = re.search(r'expiry=([^\s]+)', payload)
        if not m:
            return False
        expiry = datetime.fromisoformat(m.group(1))
        return expiry >= datetime.now()
    except Exception:
        return False


def load_license() -> bool:
    if not LICENSE_FILE.exists():
        return False
    try:
        txt = LICENSE_FILE.read_text(encoding='utf-8')
        return validate_license_content(txt.strip())
    except Exception:
        return False


def write_license_file(content: str) -> bool:
    try:
        with LICENSE_FILE.open('w', encoding='utf-8') as f:
            f.write(content)
        return True
    except Exception as e:
        log(f"Fout bij schrijven licentiebestand: {e}")
        return False


def generate_demo_license(days: int = TRIAL_DAYS) -> str:
    expiry = datetime.now() + timedelta(days=days)
    payload = f"expiry={expiry.isoformat()}"
    sig = _hmac_for_payload(payload.encode('utf-8'))
    return sig + ":" + payload


# ---------- Dev Mode helpers ----------

DEV_FILE = Path(__file__).with_suffix('.dev')

try:
    import win32crypt  # type: ignore
    _HAS_DPAPI = True
except Exception:
    _HAS_DPAPI = False


def _dpapi_encrypt(data: bytes) -> bytes:
    if _HAS_DPAPI:
        try:
            return win32crypt.CryptProtectData(data, None, None, None, None, 0)[1]
        except Exception:
            pass
    # fallback: simple XOR with key derived from LOCAL_LICENSE_SECRET
    key = hashlib.sha256(LOCAL_LICENSE_SECRET).digest()
    out = bytearray()
    for i, b in enumerate(data):
        out.append(b ^ key[i % len(key)])
    return bytes(out)


def _dpapi_decrypt(blob: bytes) -> bytes | None:
    if _HAS_DPAPI:
        try:
            return win32crypt.CryptUnprotectData(blob, None, None, None, None, 0)[1]
        except Exception:
            pass
    # fallback XOR decode
    key = hashlib.sha256(LOCAL_LICENSE_SECRET).digest()
    out = bytearray()
    for i, b in enumerate(blob):
        out.append(b ^ key[i % len(key)])
    return bytes(out)


def save_dev_record(code: str, persist: bool = True, hide: bool = True, persist_state: bool = False) -> bool:
    """Saves an encrypted dev code record. If hide=True the code will not be stored in plaintext and
    will only be shown once during generation. If persist_state=True the dev mode will be kept active across restarts."""
    try:
        record = {
            'persist': bool(persist),
            'hide': bool(hide),
            'created': datetime.now().isoformat(),
            'persist_state': bool(persist_state),
        }
        # encrypt code
        blob = _dpapi_encrypt(code.encode('utf-8'))
        record['code'] = base64.b64encode(blob).decode('ascii')
        DEV_FILE.write_text(json.dumps(record), encoding='utf-8')
        return True
    except Exception as e:
        log(f"Fout bij opslaan dev record: {e}")
        return False


def load_dev_record() -> dict | None:
    if not DEV_FILE.exists():
        return None
    try:
        txt = DEV_FILE.read_text(encoding='utf-8')
        rec = json.loads(txt)
        return rec
    except Exception as e:
        log(f"Fout bij lezen dev record: {e}")
        return None


def clear_dev_record() -> bool:
    try:
        if DEV_FILE.exists():
            DEV_FILE.unlink()
        return True
    except Exception as e:
        log(f"Fout bij verwijderen dev record: {e}")
        return False


def verify_dev_code(input_code: str) -> bool:
    rec = load_dev_record()
    if not rec or 'code' not in rec:
        return False
    try:
        blob = base64.b64decode(rec['code'])
        plain = _dpapi_decrypt(blob)
        if plain is None:
            return False
        return hmac.compare_digest(plain.decode('utf-8'), input_code)
    except Exception:
        return False


# ---------- BitLocker helpers ----------

def detect_drives() -> dict:
    """Return dictionary of drives -> status text where BitLocker appears configured."""
    rc, out = run_cmd(["manage-bde", "-status"])  # lists all volumes
    drives = {}
    if rc != 0 and not out:
        return drives

    # Split output into blocks per volume
    blocks = re.split(r"\n\s*Volume\s*[A-Z]:|\n\s*Volume\s*", out)
    # Sometimes manage-bde prints 'Volume C:' style; fallback to scanning lines
    if len(blocks) <= 1:
        # Fallback parse: find Mount Point lines and collect nearby lines
        current = None
        buf = {}
        for line in out.splitlines():
            m = re.match(r"\s*Volume\s*([A-Z]:)", line)
            if m:
                current = m.group(1)
                buf[current] = line + '\n'
            elif current:
                buf[current] += line + '\n'
        for d, b in buf.items():
            drives[d] = b
        return drives

    # More robust parse: look for 'Mount Point' and 'Percentage Encrypted' lines
    for match in re.finditer(r"(Mount Point|Volume)\s*:?\s*([A-Z]:).*?(?=\n\s*(Mount Point|Volume)|\Z)", out, re.S):
        drive = match.group(2)
        block = match.group(0)
        drives[drive] = block
    return drives


def get_drives_with_bitlocker() -> dict:
    dr = detect_drives()
    result = {}
    for d, block in dr.items():
        # Basic heuristic: presence of 'Percentage Encrypted' or 'Protection Status: On' or 'Conversion Status: Fully Encrypted'
        if re.search(r"Percentage Encrypted:\s*\d+%", block) or re.search(r"Protection Status:\s*On", block, re.I) or re.search(r"Conversion Status:\s*Fully Encrypted", block, re.I):
            result[d] = block
    return result


def get_bitlocker_status(drive: str) -> str:
    rc, out = run_cmd(["manage-bde", "-status", drive])
    if rc != 0 and not out:
        rc, out = run_cmd(["powershell", "-NoProfile", "-Command", f"Get-BitLockerVolume -MountPoint '{drive}' | Format-List | Out-String"]) 
    return out


def parse_encryption_percentage(status_output: str) -> int | None:
    m = re.search(r"Percentage Encrypted:\s*(\d+)%", status_output)
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            return None
    return None


def backup_recovery_key(drive: str, target_dir: Path = BACKUP_DIR) -> Path | None:
    """Save protectors output to a local file and return path, or None on failure."""
    target_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d-%H%M%S')
    outp = target_dir / f"recovery_{drive.replace(':','')}_{ts}.txt"
    rc, out = run_cmd(["manage-bde", "-protectors", "-get", drive])
    if rc == 0 and out:
        try:
            with outp.open('w', encoding='utf-8') as f:
                f.write(out)
            log(f"Recovery key saved to {outp}")
            return outp
        except Exception as e:
            log(f"Fout bij opslaan recovery key: {e}")
            return None
    else:
        log(f"Backup mislukte voor {drive}: {out}")
        return None


def disable_bitlocker(drive: str) -> tuple[bool, str]:
    rc, out = run_cmd(["manage-bde", "-off", drive])
    if rc == 0:
        return True, out
    rc, out = run_cmd(["powershell", "-NoProfile", "-Command", f"Disable-BitLocker -MountPoint '{drive}' | Out-String"]) 
    return (rc == 0), out


# ---------- GUI Application ----------

class BitLockerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{PRODUCT_NAME} — {COMPANY_NAME} v{VERSION}")
        self.geometry("900x600")
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        # Ensure Windows shows the app icon (not Python) by setting AppUserModelID early
        try:
            if is_windows() and hasattr(ctypes.windll, 'shell32'):
                try:
                    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_ID)
                except Exception:
                    pass
        except Exception:
            pass

        # try load logo/icon (prefer logo.ico/logo.png then icon)
        try:
            base_dir = Path(__file__).parent
            # write fallback logo files if missing
            logo_light = base_dir / 'logo_light.png'
            logo_dark = base_dir / 'logo_dark.png'
            if not logo_light.exists():
                try:
                    logo_light.write_bytes(base64.b64decode(LOGO_PNG_B64_LIGHT))
                except Exception:
                    pass
            if not logo_dark.exists():
                try:
                    logo_dark.write_bytes(base64.b64decode(LOGO_PNG_B64_DARK))
                except Exception:
                    pass

            # prefer .ico for taskbar icon; try logo.ico first
            for ico_name in ('logo.ico', 'icon.ico'):
                ico_path = base_dir.with_name(base_dir.name) / ico_name if False else base_dir / ico_name
                # (above ternary keeps IDE linters happy; we simply test base_dir/ico_name)
                ico_path = base_dir / ico_name
                if ico_path.exists():
                    try:
                        self.iconbitmap(str(ico_path))
                    except Exception:
                        try:
                            img = tk.PhotoImage(file=str(ico_path))
                            self.iconphoto(True, img)
                            self._icon_image = img
                        except Exception:
                            pass
                    break

            # Header logo images (keep references). Create thumbnails for header display if PIL available
            self._logo_light_image = None
            self._logo_dark_image = None
            self._logo_light_thumb = None
            self._logo_dark_thumb = None
            try:
                if _HAS_PIL:
                    # load with PIL and create both full and thumbnail versions
                    lp = Image.open(logo_light).convert('RGBA')
                    dp = Image.open(logo_dark).convert('RGBA')
                    # full images for iconphoto use
                    try:
                        self._logo_light_image = ImageTk.PhotoImage(lp)
                        self._logo_dark_image = ImageTk.PhotoImage(dp)
                    except Exception:
                        self._logo_light_image = None
                        self._logo_dark_image = None
                    # thumbnail for header (approx 40px height)
                    try:
                        thumb_size = (40, 40)
                        lt = lp.resize(thumb_size, Image.LANCZOS)
                        dt = dp.resize(thumb_size, Image.LANCZOS)
                        self._logo_light_thumb = ImageTk.PhotoImage(lt)
                        self._logo_dark_thumb = ImageTk.PhotoImage(dt)
                    except Exception:
                        self._logo_light_thumb = None
                        self._logo_dark_thumb = None
                else:
                    try:
                        self._logo_light_image = tk.PhotoImage(file=str(logo_light))
                    except Exception:
                        self._logo_light_image = None
                    try:
                        self._logo_dark_image = tk.PhotoImage(file=str(logo_dark))
                    except Exception:
                        self._logo_dark_image = None
                        
                    # try to subsample for a smaller header image (integer factor)
                    try:
                        if self._logo_light_image is not None:
                            self._logo_light_thumb = self._logo_light_image.subsample(max(1, int(self._logo_light_image.width()/40)))
                    except Exception:
                        self._logo_light_thumb = None
                    try:
                        if self._logo_dark_image is not None:
                            self._logo_dark_thumb = self._logo_dark_image.subsample(max(1, int(self._logo_dark_image.width()/40)))
                    except Exception:
                        self._logo_dark_thumb = None

            except Exception:
                self._logo_light_image = None
                self._logo_dark_image = None
                self._logo_light_thumb = None
                self._logo_dark_thumb = None

            # If no .ico found, ensure we have an iconphoto from logo_light (preferred) or embedded icon.png
            if not hasattr(self, '_icon_image'):
                icon_png = base_dir / 'icon.png'
                if not icon_png.exists():
                    try:
                        icon_png.write_bytes(base64.b64decode(ICON_PNG_B64))
                    except Exception:
                        pass
                try:
                    img = tk.PhotoImage(file=str(icon_png))
                    self.iconphoto(True, img)
                    self._icon_image = img
                except Exception:
                    # fallback to logo_light image
                    try:
                        if self._logo_light_image is not None:
                            self.iconphoto(True, self._logo_light_image)
                            self._icon_image = self._logo_light_image
                    except Exception:
                        pass
        except Exception:
            pass

        # Styling & fonts
        style = ttk.Style(self)
        try:
            style.theme_use('vista')
        except Exception:
            try:
                style.theme_use('clam')
            except Exception:
                pass

        # Base font sizing
        self.default_font = tkfont.nametofont("TkDefaultFont")
        try:
            self.default_font.configure(size=10)
        except Exception:
            pass

        # Theme state
        self.current_theme = 'default'

        # runtime threading/queue must exist before theme applies (theme logs)
        self.task_thread = None
        self.stop_event = threading.Event()
        self.queue = queue.Queue()

        self.apply_theme(self.current_theme)

        # Runtime state
        self.selected = {}  # drive -> tk.BooleanVar
        self.status_labels = {}  # drive -> label widget
        self.backup_done = {}  # drive -> bool

        self.task_thread = None
        self.stop_event = threading.Event()
        self.queue = queue.Queue()

        # Build UI and initialize
        self._build_ui()
        # licensing
        self.licensed = load_license()
        self.update_license_status()
        # dev mode
        self.dev_mode = False
        rec = load_dev_record()
        if rec and rec.get('persist_state'):
            self.dev_mode = True
            log('Dev Mode active from persisted state')
        self.update_dev_ui()
        self.refresh_drives()
        self.after(200, self._process_queue)

    def apply_theme(self, theme: str) -> None:
        """Apply a UI theme. Supports 'default' and 'monochrome'."""
        style = ttk.Style(self)
        if theme == 'monochrome':
            # Monochrome (black & white) modern look
            bg = '#0b0b0b'
            panel = '#111111'
            fg = '#ffffff'
            muted = '#bdbdbd'
            btn_bg = '#ffffff'
            btn_fg = '#000000'
            style.configure('TFrame', background=bg)
            style.configure('TLabel', background=bg, foreground=fg)
            style.configure('Header.TLabel', font=('Segoe UI', 18, 'bold'), foreground=fg, background=bg)
            style.configure('Subtitle.TLabel', font=('Segoe UI', 10), foreground=muted, background=bg)
            style.configure('TLabelframe.Label', font=('Segoe UI', 11, 'bold'), foreground=muted, background=bg)
            # Accent button: bold, larger, clear contrast (white bg / black text in monochrome)
            style.configure('Accent.TButton', foreground=btn_fg, background=btn_bg, font=('Segoe UI', 11, 'bold'), padding=10, relief='raised', borderwidth=1)
            style.map('Accent.TButton', 
                background=[('!disabled', btn_bg), ('active', '#e6e6e6'), ('pressed', '#dcdcdc'), ('disabled', '#777777')],
                foreground=[('!disabled', btn_fg), ('disabled', '#aaaaaa')]
            )
            # Danger button: red with clear white text and strong hover
            style.configure('Danger.TButton', foreground=btn_bg, background='#b32d2e', font=('Segoe UI', 11, 'bold'), padding=10, relief='raised', borderwidth=1)
            style.map('Danger.TButton', background=[('!disabled', '#b32d2e'), ('active', '#a02828'), ('pressed', '#882222'), ('disabled', '#777777')], foreground=[('!disabled', btn_bg), ('disabled', '#aaaaaa')])
            # Generic button style: larger font and clear contrast
            style.configure('TButton', background=panel, foreground=fg, padding=8, font=('Segoe UI', 10))
            style.map('TButton', background=[('!disabled', panel), ('active', '#2b2b2b')], foreground=[('disabled', '#888888')])
            style.configure('TCheckbutton', background=bg, foreground=fg, font=('Segoe UI', 9))
            try:
                self.configure(bg=bg)
            except Exception:
                pass
            # Text widget colors
            try:
                self.log_text.configure(bg='#111111', fg=fg, insertbackground=fg, selectbackground='#333333')
            except Exception:
                pass
            try:
                self.status_bar.configure(background=bg, foreground=fg)
            except Exception:
                pass
            # header logo (prefer thumbnail)
            try:
                if hasattr(self, 'logo_label') and self.logo_label is not None:
                    if getattr(self, '_logo_dark_thumb', None) is not None:
                        self.logo_label.configure(image=self._logo_dark_thumb)
                        self.logo_label.image = self._logo_dark_thumb
                    elif getattr(self, '_logo_dark_image', None) is not None:
                        self.logo_label.configure(image=self._logo_dark_image)
                        self.logo_label.image = self._logo_dark_image
            except Exception:
                pass
            # misc foreground updates
            try:
                self.license_status.configure(foreground=fg)
            except Exception:
                pass
            try:
                self.log_text.configure(fg=fg)
            except Exception:
                pass
            self._append_log('Theme set to Monochrome')
        else:
            # Default (green accent) modern look
            bg = '#ffffff'
            panel = '#ffffff'
            fg = '#222222'
            muted = '#4b4b4b'
            accent = '#2b7a3a'
            style.configure('TFrame', background=bg)
            style.configure('TLabel', background=bg, foreground=fg)
            style.configure('Header.TLabel', font=('Segoe UI', 18, 'bold'), foreground=accent, background=bg)
            style.configure('Subtitle.TLabel', font=('Segoe UI', 10), foreground=muted, background=bg)
            style.configure('TLabelframe.Label', font=('Segoe UI', 11, 'bold'), foreground=muted, background=bg)
            # Accent button: clear white on green, bolder and responsive
            style.configure('Accent.TButton', foreground='white', background=accent, font=('Segoe UI', 11, 'bold'), padding=10, relief='raised', borderwidth=1)
            style.map('Accent.TButton', background=[('!disabled', accent), ('active', '#2f8c30'), ('pressed', '#276d26'), ('disabled', '#999999')], foreground=[('disabled', '#eeeeee')])
            style.configure('Danger.TButton', foreground='white', background='#b32d2e', font=('Segoe UI', 11, 'bold'), padding=10, relief='raised', borderwidth=1)
            style.map('Danger.TButton', background=[('!disabled', '#b32d2e'), ('active', '#9b2526'), ('pressed', '#7a1f1f')], foreground=[('disabled', '#dddddd')])
            style.configure('TButton', background=panel, foreground=fg, padding=8, font=('Segoe UI', 10))
            style.map('TButton', background=[('!disabled', panel), ('active', '#f0f0f0')], foreground=[('disabled', '#888888')])
            style.configure('TCheckbutton', background=bg, foreground=fg, font=('Segoe UI', 9))
            try:
                self.configure(bg='SystemButtonFace')
            except Exception:
                pass
            try:
                self.log_text.configure(bg='#fbfbfb', fg=fg, insertbackground=fg, selectbackground='#ececec')
            except Exception:
                pass
            try:
                self.status_bar.configure(background='#f7f7f7', foreground='#444444')
            except Exception:
                pass
            # header logo (prefer thumbnail)
            try:
                if hasattr(self, 'logo_label') and self.logo_label is not None:
                    if getattr(self, '_logo_light_thumb', None) is not None:
                        self.logo_label.configure(image=self._logo_light_thumb)
                        self.logo_label.image = self._logo_light_thumb
                    elif getattr(self, '_logo_light_image', None) is not None:
                        self.logo_label.configure(image=self._logo_light_image)
                        self.logo_label.image = self._logo_light_image
            except Exception:
                pass
            # misc foreground updates
            try:
                self.license_status.configure(foreground=fg)
            except Exception:
                pass
            try:
                self.log_text.configure(fg=fg)
            except Exception:
                pass
            self._append_log('Theme set to Default')

    def set_theme(self, theme: str) -> None:
        self.current_theme = theme
        self.apply_theme(theme)

    def set_app_icon(self) -> None:
        """Ensure the application window and taskbar show the app icon (logo.ico or embedded image)."""
        try:
            base_dir = Path(__file__).parent
            ico = base_dir / 'logo.ico'
            if ico.exists():
                try:
                    self.iconbitmap(str(ico))
                except Exception:
                    pass
            # also ensure iconphoto uses the full logo image if available
            if hasattr(self, '_logo_light_image') and self._logo_light_image is not None:
                try:
                    self.iconphoto(True, self._logo_light_image)
                except Exception:
                    pass
            elif hasattr(self, '_icon_image') and self._icon_image is not None:
                try:
                    self.iconphoto(True, self._icon_image)
                except Exception:
                    pass
        except Exception:
            pass

    def toggle_theme(self) -> None:
        self.set_theme('monochrome' if self.current_theme != 'monochrome' else 'default')

    def _build_ui(self):
        # Header with app title
        header = ttk.Frame(self, padding=(12, 10))
        header.pack(fill='x')
        # Header logo + title
        self.logo_label = None
        # choose thumbnail for header (smaller size)
        logo_img = getattr(self, '_logo_light_thumb', None) if self.current_theme != 'monochrome' else getattr(self, '_logo_dark_thumb', None)
        # fallback to full image if thumbnail not available
        if not logo_img:
            logo_img = getattr(self, '_logo_light_image', None) if self.current_theme != 'monochrome' else getattr(self, '_logo_dark_image', None)
        if logo_img:
            # use a plain tk.Label for image
            self.logo_label = tk.Label(header, image=logo_img)
            self.logo_label.image = logo_img
            self.logo_label.pack(side='left', padx=(0,8))
        title = ttk.Label(header, text=PRODUCT_NAME, style='Header.TLabel')
        title.pack(side='left')
        subtitle = ttk.Label(header, text=f"{COMPANY_NAME} — v{VERSION}", style='Subtitle.TLabel')
        subtitle.pack(side='left', padx=8)

        # Menus (View: themes + Help docs)
        menubar = tk.Menu(self)
        viewmenu = tk.Menu(menubar, tearoff=0)
        viewmenu.add_radiobutton(label='Default theme', command=lambda: self.set_theme('default'))
        viewmenu.add_radiobutton(label='Monochrome (zwart/wit)', command=lambda: self.set_theme('monochrome'))
        menubar.add_cascade(label='View', menu=viewmenu)

        helpmenu = tk.Menu(menubar, tearoff=0)
        helpmenu.add_command(label='View README', command=self.show_readme)
        helpmenu.add_command(label='View EULA', command=self.show_eula)
        helpmenu.add_command(label='View Terms', command=self.show_terms)
        menubar.add_cascade(label='Help', menu=helpmenu)
        self.config(menu=menubar)

        top = ttk.Frame(self)
        top.pack(fill='x', padx=10, pady=6)

        refresh_btn = ttk.Button(top, text='Refresh drives', command=self.refresh_drives, style='TButton')
        refresh_btn.pack(side='left')

        # License controls
        self.license_status = ttk.Label(top, text='License: unknown')
        self.license_status.pack(side='right', padx=6)
        self.license_btn = ttk.Button(top, text='Enter License', command=self.enter_license, style='Accent.TButton')
        self.license_btn.pack(side='right')
        self.demo_btn = ttk.Button(top, text='Demo license', command=self.generate_demo_license_ui, style='Accent.TButton')
        self.demo_btn.pack(side='right', padx=6)

        self.relaunch_btn = ttk.Button(top, text='Relaunch as Admin', command=self.relaunch_as_admin, style='TButton')
        self.relaunch_btn.pack(side='right')

        theme_btn = ttk.Button(top, text='Monochrome', command=self.toggle_theme, style='TButton')
        theme_btn.pack(side='right', padx=6)

        about_btn = ttk.Button(top, text='About', command=self.show_about, style='TButton')
        about_btn.pack(side='right', padx=6)

        mid = ttk.Frame(self)
        mid.pack(fill='both', expand=True, padx=10, pady=6)

        left = ttk.LabelFrame(mid, text='Drives (selecteer)')
        left.pack(side='left', fill='y', padx=6, pady=6)

        self.drive_container = ttk.Frame(left)
        self.drive_container.pack(fill='both', expand=True)

        right = ttk.Frame(mid)
        right.pack(side='right', fill='both', expand=True)

        agree_frame = ttk.Frame(right)
        agree_frame.pack(fill='x')
        self.agree_var = tk.BooleanVar(value=False)
        cb = ttk.Checkbutton(agree_frame, text='Ik begrijp de risico\'s en heb een backup gemaakt van mijn recovery keys', variable=self.agree_var, command=self._update_start_state)
        cb.pack(side='left', fill='x', expand=True)

        btns = ttk.Frame(right)
        btns.pack(fill='x', pady=6)
        self.backup_btn = ttk.Button(btns, text='Backup geselecteerde', command=self.backup_selected, style='Accent.TButton')
        self.backup_btn.pack(side='left', padx=4)
        self.start_btn = ttk.Button(btns, text='Start', command=self.start_selected, state='disabled', style='Accent.TButton')
        self.start_btn.pack(side='left', padx=4)
        self.cancel_btn = ttk.Button(btns, text='Annuleer', command=self.cancel, state='disabled', style='Danger.TButton')
        self.cancel_btn.pack(side='left', padx=4)

        # Dev Mode Controls
        dev_frame = ttk.LabelFrame(right, text='Dev Mode')
        dev_frame.pack(fill='x', pady=6)
        self.dev_label = ttk.Label(dev_frame, text='Dev Mode: Off')
        self.dev_label.pack(side='left', padx=6)
        self.dev_unlock_btn = ttk.Button(dev_frame, text='Unlock Dev Mode', command=self.enter_dev_code_ui, style='TButton')
        self.dev_unlock_btn.pack(side='left', padx=4)
        self.dev_gen_btn = ttk.Button(dev_frame, text='Set/Generate Code', command=self.generate_dev_code_ui, style='Accent.TButton')
        self.dev_gen_btn.pack(side='left', padx=4)
        self.dev_clear_btn = ttk.Button(dev_frame, text='Clear saved code', command=self.clear_dev_code_ui, style='TButton')
        self.dev_clear_btn.pack(side='left', padx=4)
        self.dev_reveal_btn = ttk.Button(dev_frame, text='Reveal saved code', command=self.reveal_dev_code_ui, style='TButton')
        self.dev_reveal_btn.pack(side='left', padx=4)

        self.progress_box = ttk.LabelFrame(right, text='Voortgang / Log')
        self.progress_box.pack(fill='both', expand=True, pady=6)
        self.log_text = tk.Text(self.progress_box, height=18, state='disabled')
        self.log_text.pack(fill='both', expand=True)
        self.status_bar = ttk.Label(self, text='Ready', relief='sunken', anchor='w')
        self.status_bar.pack(side='bottom', fill='x')

    def _append_log(self, message: str):
        log(message)
        self.queue.put(('log', message))

    def _process_queue(self):
        try:
            while True:
                item = self.queue.get_nowait()
                typ, msg = item
                if typ == 'log':
                    self.log_text.configure(state='normal')
                    self.log_text.insert('end', msg + '\n')
                    self.log_text.see('end')
                    self.log_text.configure(state='disabled')
                    try:
                        self.status_bar.configure(text=msg[:120])
                    except Exception:
                        pass
                elif typ == 'status':
                    drive, text = msg
                    if drive in self.status_labels:
                        self.status_labels[drive].configure(text=text)
        except queue.Empty:
            pass
        self.after(200, self._process_queue)

    def update_dev_ui(self):
        rec = load_dev_record()
        text = 'Dev Mode: On' if getattr(self, 'dev_mode', False) else 'Dev Mode: Off'
        if rec:
            if rec.get('persist'):
                text += ' (saved)'
            if rec.get('hide'):
                text += ' [hidden]'
        self.dev_label.configure(text=text)
        # Reveal button only enabled if saved and not hidden
        if rec and not rec.get('hide'):
            self.dev_reveal_btn.configure(state='normal')
        else:
            self.dev_reveal_btn.configure(state='disabled')
        self._update_start_state()

    def enter_dev_code_ui(self):
        # masked input prompt
        code = simpledialog.askstring('Enter dev code', 'Voer je dev-code in:', show='*', parent=self)
        if not code:
            return
        ok = verify_dev_code(code)
        if ok:
            self.dev_mode = True
            self._append_log('Dev Mode ontgrendeld (sessie).')
            messagebox.showinfo('Dev Mode', 'Dev Mode is nu actief voor deze sessie.')
            self.update_dev_ui()
        else:
            messagebox.showerror('Dev Mode', 'Onjuiste code of geen dev code ingesteld.')

    def generate_dev_code_ui(self):
        # ask whether to generate or enter custom
        if messagebox.askyesno('Generate', 'Wil je een willekeurige code genereren? (Nee = voer eigen code in)'):
            code = secrets.token_urlsafe(10)
        else:
            code = simpledialog.askstring('Custom code', 'Voer gewenste dev-code in:', parent=self)
            if not code:
                return
        hide = messagebox.askyesno('Hide code', 'Wil je dat de code verborgen wordt (niet later zichtbaar)?')
        persist_state = messagebox.askyesno('Persist dev', 'Moet Dev Mode actief blijven na herstart tot je het wist?')
        ok = save_dev_record(code, persist=True, hide=hide, persist_state=persist_state)
        if ok:
            # show code once if it was generated or if user didn't hide
            if not hide:
                messagebox.showinfo('Dev Code', f'De code is opgeslagen en is: {code}\nBewaar deze veilig.')
            else:
                # show once and warn
                messagebox.showinfo('Dev Code', f'De code is opgeslagen en wordt verborgen; sla hem nu op. Code: {code}')
            self._append_log('Dev code opgeslagen (verborgen: %s; persistent: %s)' % (hide, persist_state))
            # if user wants to keep dev mode active now, set it
            if persist_state:
                self.dev_mode = True
            self.update_dev_ui()
        else:
            messagebox.showerror('Dev', 'Kon dev code niet opslaan.')

    def clear_dev_code_ui(self):
        if not messagebox.askyesno('Clear', 'Weet je zeker dat je de opgeslagen dev-code wilt verwijderen?'):
            return
        ok = clear_dev_record()
        if ok:
            self.dev_mode = False
            self._append_log('Dev code verwijderd.')
            messagebox.showinfo('Clear', 'Dev code verwijderd.')
            self.update_dev_ui()
        else:
            messagebox.showerror('Clear', 'Kon dev code niet verwijderen.')

    def reveal_dev_code_ui(self):
        rec = load_dev_record()
        if not rec:
            messagebox.showinfo('Reveal', 'Geen opgeslagen dev code gevonden.')
            return
        if rec.get('hide'):
            messagebox.showwarning('Reveal', 'De opgeslagen code is gemarkeerd als verborgen en kan niet worden onthuld via de UI.')
            return
        try:
            blob = base64.b64decode(rec['code'])
            plain = _dpapi_decrypt(blob)
            if plain is None:
                messagebox.showerror('Reveal', 'Kon code niet ontcijferen.')
                return
            code = plain.decode('utf-8')
            # show code once
            messagebox.showinfo('Stored dev code', f'De opgeslagen code is: {code}')
        except Exception as e:
            messagebox.showerror('Reveal', f'Fout: {e}')

    def refresh_drives(self):
        """Detect drives and rebuild checkbuttons"""
        # Ensure correct app icon is set while we search
        try:
            self.set_app_icon()
        except Exception:
            pass
        self.status_bar.configure(text='Zoeken naar schijven...')
        self._append_log("Drives detecteren...")
        found = get_drives_with_bitlocker()
        # restore status
        try:
            self.set_app_icon()
            self.status_bar.configure(text='Ready')
        except Exception:
            pass
        # Clear existing
        for child in self.drive_container.winfo_children():
            child.destroy()
        self.selected.clear()
        self.status_labels.clear()
        self.backup_done.clear()

        if not found:
            lbl = ttk.Label(self.drive_container, text='Geen BitLocker-geschakelde volumes gevonden')
            lbl.pack()
            self._append_log('Geen schijven met BitLocker gevonden.')
            return

        for d, block in sorted(found.items()):
            var = tk.BooleanVar(value=False)
            frame = ttk.Frame(self.drive_container)
            frame.pack(fill='x', pady=2)
            cb = ttk.Checkbutton(frame, text=d, variable=var, command=self._update_start_state)
            cb.pack(side='left')
            stat = ttk.Label(frame, text='Status onbekend')
            stat.pack(side='left', padx=8)
            self.selected[d] = var
            self.status_labels[d] = stat
            self.backup_done[d] = False
            # initialize label with current percentage if available
            pct = parse_encryption_percentage(block)
            if pct is not None:
                stat.configure(text=f'Encrypted: {pct}%')

        self._update_start_state()

    def _update_start_state(self):
        # Start is enabled only if: at least one drive selected, agree checked, and backups done for all selected drives
        any_selected = any(v.get() for v in self.selected.values())
        if not any_selected or not self.agree_var.get():
            self.start_btn.configure(state='disabled')
            return
        # ensure backups done
        for d, v in self.selected.items():
            if v.get() and not self.backup_done.get(d, False):
                self.start_btn.configure(state='disabled')
                return
        if not is_admin():
            self.start_btn.configure(state='disabled')
            self._append_log('Script is niet als Administrator gestart; Start uitgeschakeld.')
            return
        # Require a valid license to perform disabling operations, unless Dev Mode is active
        if not getattr(self, 'licensed', False) and not getattr(self, 'dev_mode', False):
            self.start_btn.configure(state='disabled')
            self._append_log('Geen geldige licentie gevonden; start uitgeschakeld. (Of activeer Dev Mode)')
            return
        self.start_btn.configure(state='normal')

    def relaunch_as_admin(self):
        if is_admin():
            messagebox.showinfo('Admin', 'Je draait al als Administrator.')
            return
        try:
            # Relaunch this script elevated
            params = ' '.join([f'"{arg}"' for arg in sys.argv[1:]])
            ctypes.windll.shell32.ShellExecuteW(None, 'runas', sys.executable, f'"{__file__}" {params}', None, 1)  # type: ignore
            self._append_log('Script wordt opnieuw gestart als Administrator...')
            self.destroy()
        except Exception as e:
            messagebox.showerror('Fout', f'Kan niet opnieuw starten als Administrator: {e}')

    def update_license_status(self):
        self.licensed = load_license()
        if self.licensed:
            self.license_status.configure(text=f'License: Licensed')
            self._append_log('Licentie: actief')
        else:
            self.license_status.configure(text=f'License: Demo/Unlicensed')
            self._append_log('Licentie: niet gevonden of verlopen')
        self._update_start_state()

    def enter_license(self):
        key = simpledialog.askstring('Licentie invoeren', 'Plak je licentiesleutel (of inhoud van .lic bestand):', parent=self)
        if not key:
            return
        if validate_license_content(key.strip()):
            if write_license_file(key.strip()):
                self._append_log('Licentie opgeslagen en geactiveerd.')
                messagebox.showinfo('Licentie', 'Licentie geaccepteerd. Herstart de app indien nodig.')
                self.update_license_status()
            else:
                messagebox.showerror('Licentie', 'Kan licentiebestand niet opslaan.')
        else:
            messagebox.showerror('Licentie', 'Ongeldige of verlopen licentiesleutel.')

    def generate_demo_license_ui(self):
        if not messagebox.askyesno('Demo licentie', f'Maak een demo-licentie voor {TRIAL_DAYS} dagen? (alleen voor testen)'):
            return
        content = generate_demo_license(TRIAL_DAYS)
        ok = write_license_file(content)
        if ok:
            self._append_log(f'Demo licentie gemaakt (geldigheid {TRIAL_DAYS} dagen).')
            messagebox.showinfo('Demo', f'Demo licentie aangemaakt: {LICENSE_FILE}')
            self.update_license_status()
        else:
            messagebox.showerror('Demo', 'Kon demo licentie niet schrijven.')

    def backup_selected(self):
        to_backup = [d for d, v in self.selected.items() if v.get()]
        if not to_backup:
            messagebox.showinfo('Backup', 'Selecteer eerst één of meerdere schijven om te backuppen.')
            return
        # Ask where to save (optional)
        target = filedialog.askdirectory(title='Kies map om backups op te slaan (annuleren = default)', initialdir=str(BACKUP_DIR))
        target_dir = Path(target) if target else BACKUP_DIR
        self._append_log(f'Backup starten voor: {to_backup} -> map: {target_dir}')

        def do_backup():
            for d in to_backup:
                if self.stop_event.is_set():
                    self._append_log('Backup geannuleerd door gebruiker')
                    return
                path = backup_recovery_key(d, target_dir)
                if path:
                    self.backup_done[d] = True
                    self._append_log(f'Backup gelukt: {d} -> {path}')
                    self.queue.put(('status', (d, 'Backup aanwezig')))
                else:
                    self._append_log(f'Backup mislukt voor {d}')
            self._update_start_state()

        threading.Thread(target=do_backup, daemon=True).start()

    def start_selected(self):
        to_start = [d for d, v in self.selected.items() if v.get()]
        if not to_start:
            messagebox.showinfo('Start', 'Selecteer eerst één of meerdere schijven om uit te schakelen.')
            return
        if not self.agree_var.get():
            messagebox.showwarning('Overeenkomst', 'Je moet akkoord gaan met de risico\'s en backups hebben gemaakt.')
            return
        # Ensure backups done for each
        missing = [d for d in to_start if not self.backup_done.get(d, False)]
        if missing:
            messagebox.showwarning('Backup', f'Make backups first for: {missing}')
            return

        if not messagebox.askyesno('Bevestig', f'Weet je zeker dat je BitLocker wilt uitschakelen voor: {to_start}? Dit decrypt de schijven.'):
            return

        self.stop_event.clear()
        self.start_btn.configure(state='disabled')
        self.cancel_btn.configure(state='normal')
        self._append_log(f'Start uitschakelen voor: {to_start}')

        def worker():
            for d in to_start:
                if self.stop_event.is_set():
                    self._append_log('Proces geannuleerd door gebruiker')
                    break
                self.queue.put(('status', (d, 'Uitschakelen gestart')))
                ok, out = disable_bitlocker(d)
                self._append_log(f'Uitschakel commando uitgevoerd voor {d}. Succes={ok}')
                if not ok:
                    self._append_log(f'Fout tijdens uitschakelen {d}: {out}')
                    continue
                # Monitor progress
                while not self.stop_event.is_set():
                    st = get_bitlocker_status(d)
                    pct = parse_encryption_percentage(st)
                    if pct is not None:
                        self.queue.put(('status', (d, f'Encrypted: {pct}%')))
                        if pct == 0:
                            self._append_log(f'Decryptie voltooid voor {d}')
                            break
                    else:
                        self._append_log(f'Kan encryptiepercentage niet bepalen voor {d}; bekijk status handmatig')
                        break
                    time.sleep(CHECK_INTERVAL)
            self._append_log('Alle geselecteerde schijven verwerkt of proces gestopt.')
            self.cancel_btn.configure(state='disabled')
            self._update_start_state()

        self.task_thread = threading.Thread(target=worker, daemon=True)
        self.task_thread.start()

    def cancel(self):
        if messagebox.askyesno('Annuleer', 'Weet je zeker dat je wilt annuleren?'):
            self.stop_event.set()
            self._append_log('Annuleerverzoek ingediend...')
            self.cancel_btn.configure(state='disabled')

    def on_close(self):
        if self.task_thread and self.task_thread.is_alive():
            if not messagebox.askyesno('Afsluiten', 'Er loopt een proces. Wil je echt afsluiten (dit annuleert het proces)?'):
                return
            self.stop_event.set()
        self.destroy()

    def show_about(self):
        info = f"{PRODUCT_NAME} - {COMPANY_NAME}\nVersion: {VERSION}\n\nLicence: see EULA.txt"
        if messagebox.askyesno('About', info + '\n\nBekijk EULA?'):
            try:
                subprocess.Popen(['notepad.exe', str(Path(__file__).with_name('EULA.txt'))])
            except Exception as e:
                messagebox.showerror('Fout', f'Kan EULA niet openen: {e}')

    def _show_text_file(self, title: str, file_path: Path) -> None:
        if not file_path.exists():
            messagebox.showerror(title, f'Bestand niet gevonden: {file_path}')
            return
        try:
            txt = file_path.read_text(encoding='utf-8')
        except Exception as e:
            messagebox.showerror(title, f'Kan bestand niet openen: {e}')
            return
        win = tk.Toplevel(self)
        win.title(title)
        win.geometry('700x500')
        frm = ttk.Frame(win, padding=8)
        frm.pack(fill='both', expand=True)
        text = tk.Text(frm, wrap='word')
        text.insert('1.0', txt)
        text.configure(state='disabled')
        text.pack(fill='both', expand=True, side='left')
        sb = ttk.Scrollbar(frm, orient='vertical', command=text.yview)
        sb.pack(side='right', fill='y')
        text['yscrollcommand'] = sb.set
        btn_frame = ttk.Frame(win)
        btn_frame.pack(fill='x')
        ttk.Button(btn_frame, text='Open in Notepad', command=lambda: subprocess.Popen(['notepad.exe', str(file_path)])).pack(side='left', padx=4)
        ttk.Button(btn_frame, text='Close', command=win.destroy).pack(side='right', padx=4)

    def show_eula(self):
        self._show_text_file('EULA', Path(__file__).with_name('EULA.txt'))

    def show_terms(self):
        self._show_text_file('Terms of Service', Path(__file__).with_name('TERMS.txt'))

    def show_readme(self):
        self._show_text_file('README', Path(__file__).with_name('README.md'))


# ---------- Main ----------

def main():
    if not is_windows():
        print('Dit script is alleen voor Windows.')
        sys.exit(1)

    # CLI helper: create demo license
    if '--demo-license' in sys.argv:
        content = generate_demo_license(TRIAL_DAYS)
        if write_license_file(content):
            print(f'Demo licentie aangemaakt in {LICENSE_FILE}')
            sys.exit(0)
        else:
            print('Kon demo licentie niet aanmaken')
            sys.exit(1)

    # CLI helper: set dev code
    if '--set-dev-code' in sys.argv:
        try:
            idx = sys.argv.index('--set-dev-code')
            code = sys.argv[idx+1]
        except Exception:
            print('Usage: --set-dev-code <code> [--hide] [--persist-state]')
            sys.exit(1)
        hide = '--hide' in sys.argv
        persist_state = '--persist-state' in sys.argv
        ok = save_dev_record(code, persist=True, hide=hide, persist_state=persist_state)
        if ok:
            print('Dev code opgeslagen (hidden=%s, persist=%s)' % (hide, persist_state))
            sys.exit(0)
        else:
            print('Kon dev code niet opslaan')
            sys.exit(1)

    if '--clear-dev' in sys.argv:
        if clear_dev_record():
            print('Dev code verwijderd')
            sys.exit(0)
        else:
            print('Kon dev code niet verwijderen')
            sys.exit(1)

    app = BitLockerApp()
    if not is_admin():
        app._append_log('LET OP: script draait niet als Administrator; sommige acties zijn uitgeschakeld. Gebruik "Relaunch as Admin" om te verhogen.')
    app.mainloop()


if __name__ == '__main__':
    main()
