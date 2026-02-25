"""
FirmaPDF v1.1
Utilidad para separar, sellar y firmar digitalmente documentos PDF
con certificado digital FNMT (.pfx/.p12 o almacén de Windows).

Uso: python FirmaPDF.py
Empaquetado: pyinstaller --onefile --windowed --noupx --name "FirmaPDF" FirmaPDF.py
"""

import os
import sys
import io
import re
import hashlib
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from datetime import datetime
from pathlib import Path

HAS_FITZ = False
try:
    import fitz
    HAS_FITZ = True
except ImportError:
    pass


def _check_deps():
    missing = []
    for mod in ('pypdf', 'reportlab', 'pyhanko'):
        try:
            __import__(mod)
        except ImportError:
            missing.append(mod)
    if missing:
        msg = (
            "Faltan dependencias:\n\n" + ", ".join(missing)
            + "\n\nInstálalas con:\npip install " + " ".join(missing)
        )
        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("Dependencias", msg)
            root.destroy()
        except Exception:
            print(msg)
        sys.exit(1)


_check_deps()

from pypdf import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.units import mm
from reportlab.lib.colors import Color, HexColor
from pyhanko.sign import signers, fields
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

ACCENT = '#1a5276'
BG_FILL = Color(0.96, 0.96, 0.96, alpha=0.9)
BORDER_GRAY = Color(0.75, 0.75, 0.75)
TEXT_DARK = Color(0.2, 0.2, 0.2)


# ── Windows Certificate Store (CNG) ─────────────────────────────────────

HAS_WIN_CERT_STORE = False

if sys.platform == 'win32':
    try:
        import ctypes
        from ctypes import wintypes

        _crypt32 = ctypes.windll.crypt32
        _cryptui = ctypes.windll.cryptui
        _ncrypt = ctypes.windll.ncrypt

        _CERT_STORE_PROV_SYSTEM_W = 10
        _CERT_SYS_STORE_CU = 0x00010000
        _CRYPT_NCRYPT_KEY_FLAG = 0x00020000
        _CERT_NCRYPT_KEY_SPEC = 0xFFFFFFFF
        _BCRYPT_PAD_PKCS1 = 0x00000002
        _NTE_CANCELLED = 0x80090014

        _HASH_ALG = {
            'sha1': 'SHA1', 'sha256': 'SHA256',
            'sha384': 'SHA384', 'sha512': 'SHA512',
        }

        class _CERT_CTX(ctypes.Structure):
            _fields_ = [
                ("dwCertEncodingType", wintypes.DWORD),
                ("pbCertEncoded", ctypes.c_void_p),
                ("cbCertEncoded", wintypes.DWORD),
                ("pCertInfo", ctypes.c_void_p),
                ("hCertStore", ctypes.c_void_p),
            ]

        class _PKCS1_PAD(ctypes.Structure):
            _fields_ = [("pszAlgId", ctypes.c_wchar_p)]

        # Function signatures
        _crypt32.CertOpenStore.restype = ctypes.c_void_p
        _crypt32.CertOpenStore.argtypes = [
            ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
            wintypes.DWORD, ctypes.c_wchar_p,
        ]
        _cryptui.CryptUIDlgSelectCertificateFromStore.restype = ctypes.c_void_p
        _cryptui.CryptUIDlgSelectCertificateFromStore.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_wchar_p,
            ctypes.c_wchar_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        ]
        _crypt32.CryptAcquireCertificatePrivateKey.restype = wintypes.BOOL
        _crypt32.CryptAcquireCertificatePrivateKey.argtypes = [
            ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.BOOL),
        ]
        _ncrypt.NCryptSignHash.restype = ctypes.c_long
        _ncrypt.NCryptSignHash.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
            wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD), wintypes.DWORD,
        ]
        _ncrypt.NCryptFreeObject.restype = ctypes.c_long
        _ncrypt.NCryptFreeObject.argtypes = [ctypes.c_void_p]
        _crypt32.CertFreeCertificateContext.restype = wintypes.BOOL
        _crypt32.CertFreeCertificateContext.argtypes = [ctypes.c_void_p]
        _crypt32.CertCloseStore.restype = wintypes.BOOL
        _crypt32.CertCloseStore.argtypes = [ctypes.c_void_p, wintypes.DWORD]

        HAS_WIN_CERT_STORE = True
    except OSError:
        pass


class WinCertSession:
    """Windows certificate store session: select + sign via CNG."""

    def __init__(self):
        self._store = None
        self._cert_ptr = None
        self._key_handle = None
        self._free_key = False
        self.cert_der = None
        self.subject = ""
        self.key_algo = 'rsa'
        self.key_bits = 2048

    def select(self, hwnd=None):
        """Open native Windows certificate picker. Returns True on selection."""
        self.close()
        self._store = _crypt32.CertOpenStore(
            _CERT_STORE_PROV_SYSTEM_W, 0, None, _CERT_SYS_STORE_CU, "MY",
        )
        if not self._store:
            raise OSError("No se pudo abrir el almacén de certificados.")

        self._cert_ptr = _cryptui.CryptUIDlgSelectCertificateFromStore(
            self._store, hwnd,
            "Seleccionar certificado",
            "Seleccione el certificado digital para firmar:",
            0, 0, None,
        )
        if not self._cert_ptr:
            self.close()
            return False

        ctx = _CERT_CTX.from_address(self._cert_ptr)
        raw = (ctypes.c_ubyte * ctx.cbCertEncoded).from_address(ctx.pbCertEncoded)
        self.cert_der = bytes(raw)

        from asn1crypto import x509 as asn1_x509
        cert = asn1_x509.Certificate.load(self.cert_der)
        self.subject = cert.subject.human_friendly
        self.key_algo = cert.public_key.algorithm
        self.key_bits = cert.public_key.bit_size

        key_h = ctypes.c_void_p()
        spec = wintypes.DWORD()
        free = wintypes.BOOL()
        ok = _crypt32.CryptAcquireCertificatePrivateKey(
            self._cert_ptr, _CRYPT_NCRYPT_KEY_FLAG, None,
            ctypes.byref(key_h), ctypes.byref(spec), ctypes.byref(free),
        )
        if not ok:
            raise OSError(
                "No se pudo obtener la clave privada del certificado.\n"
                "Verifique que el certificado tiene clave privada asociada."
            )
        if spec.value != _CERT_NCRYPT_KEY_SPEC:
            raise ValueError(
                "Proveedor criptográfico no compatible.\n"
                "Exporte el certificado como .pfx y use el modo Archivo."
            )
        self._key_handle = key_h.value
        self._free_key = bool(free.value)
        return True

    def sign_hash(self, hash_bytes, digest_algorithm):
        """Sign a pre-computed hash using the NCrypt private key."""
        alg = _HASH_ALG.get(digest_algorithm.lower())
        if not alg:
            raise ValueError(f"Algoritmo no soportado: {digest_algorithm}")

        h_arr = (ctypes.c_ubyte * len(hash_bytes))(*hash_bytes)

        if self.key_algo == 'rsa':
            pad = _PKCS1_PAD()
            pad.pszAlgId = alg
            p_pad = ctypes.byref(pad)
            flags = _BCRYPT_PAD_PKCS1
        else:
            p_pad = None
            flags = 0

        sz = wintypes.DWORD()
        st = _ncrypt.NCryptSignHash(
            self._key_handle, p_pad, h_arr, len(hash_bytes),
            None, 0, ctypes.byref(sz), flags,
        )
        if st:
            self._raise(st)

        sig = (ctypes.c_ubyte * sz.value)()
        actual = wintypes.DWORD()
        st = _ncrypt.NCryptSignHash(
            self._key_handle, p_pad, h_arr, len(hash_bytes),
            sig, sz.value, ctypes.byref(actual), flags,
        )
        if st:
            self._raise(st)

        raw = bytes(sig[:actual.value])
        if self.key_algo != 'rsa':
            from asn1crypto.algos import DSASignature
            half = len(raw) // 2
            r = int.from_bytes(raw[:half], 'big')
            s = int.from_bytes(raw[half:], 'big')
            raw = DSASignature({'r': r, 's': s}).dump()
        return raw

    @staticmethod
    def _raise(status):
        code = status & 0xFFFFFFFF
        if code == _NTE_CANCELLED:
            raise ValueError("Operación cancelada por el usuario.")
        raise OSError(f"Error de firma digital (NCrypt): 0x{code:08X}")

    def close(self):
        if self._free_key and self._key_handle:
            _ncrypt.NCryptFreeObject(self._key_handle)
        self._key_handle = None
        if self._cert_ptr:
            _crypt32.CertFreeCertificateContext(self._cert_ptr)
        self._cert_ptr = None
        if self._store:
            _crypt32.CertCloseStore(self._store, 0)
        self._store = None

    def __del__(self):
        self.close()


class WindowsSigner(signers.Signer):
    """pyhanko Signer backed by the Windows CNG key store."""

    def __init__(self, session: WinCertSession):
        from asn1crypto import x509 as asn1_x509
        cert = asn1_x509.Certificate.load(session.cert_der)
        super().__init__(signing_cert=cert)
        self._session = session

    async def async_sign_raw(self, data, digest_algorithm, dry_run=False):
        if dry_run:
            return b'\x00' * max(self._session.key_bits // 8, 72)
        h = hashlib.new(digest_algorithm)
        h.update(data)
        return self._session.sign_hash(h.digest(), digest_algorithm)


# ── Stamp overlay ────────────────────────────────────────────────────────

def _crear_sello(ancho, alto, lineas, posicion, stamp_rect=None):
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(ancho, alto))
    if posicion == 'zona' and stamp_rect:
        _sello_zona(c, ancho, alto, lineas, stamp_rect)
    elif posicion == 'inferior':
        _sello_inferior(c, ancho, alto, lineas)
    else:
        _sello_izquierda(c, ancho, alto, lineas)
    c.save()
    buf.seek(0)
    return buf


def _sello_inferior(c, ancho, alto, lineas):
    margen_h = min(15 * mm, ancho * 0.05)
    margen_v = min(10 * mm, alto * 0.025)
    interlinea = 4.5 * mm
    pad = 4 * mm

    box_h = len(lineas) * interlinea + 2 * pad + mm
    box_w = max(ancho - 2 * margen_h, 20 * mm)
    radius = min(1.5 * mm, box_w / 4, box_h / 4)

    c.setFillColor(BG_FILL)
    c.setStrokeColor(BORDER_GRAY)
    c.setLineWidth(0.4)
    c.roundRect(margen_h, margen_v, box_w, box_h, radius, fill=1, stroke=1)

    c.setStrokeColor(HexColor(ACCENT))
    c.setLineWidth(1.2)
    c.line(
        margen_h + radius, margen_v + box_h,
        margen_h + box_w - radius, margen_v + box_h,
    )

    tx = margen_h + pad + mm
    ty = margen_v + box_h - pad - 3 * mm
    for i, ln in enumerate(lineas):
        if i == 0:
            c.setFont('Helvetica-Bold', 9)
            c.setFillColor(HexColor(ACCENT))
        else:
            c.setFont('Helvetica', 8)
            c.setFillColor(TEXT_DARK)
        c.drawString(tx, ty - i * interlinea, ln)


def _sello_izquierda(c, ancho, alto, lineas):
    margen = min(6 * mm, ancho * 0.02)
    interlinea = 4 * mm
    pad = 3 * mm

    box_w = len(lineas) * interlinea + 2 * pad + mm
    box_h = min(alto * 0.5, alto - 60 * mm)
    box_h = max(box_h, 40 * mm)
    box_y = (alto - box_h) / 2
    radius = min(1.5 * mm, box_w / 4, box_h / 4)

    c.setFillColor(BG_FILL)
    c.setStrokeColor(BORDER_GRAY)
    c.setLineWidth(0.4)
    c.roundRect(margen, box_y, box_w, box_h, radius, fill=1, stroke=1)

    c.setStrokeColor(HexColor(ACCENT))
    c.setLineWidth(1.2)
    c.line(
        margen + box_w, box_y + radius,
        margen + box_w, box_y + box_h - radius,
    )

    c.saveState()
    c.translate(margen + pad + 2 * mm, box_y + box_h / 2)
    c.rotate(90)
    for i, ln in enumerate(lineas):
        if i == 0:
            c.setFont('Helvetica-Bold', 8)
            c.setFillColor(HexColor(ACCENT))
        else:
            c.setFont('Helvetica', 7)
            c.setFillColor(TEXT_DARK)
        c.drawCentredString(0, -i * interlinea, ln)
    c.restoreState()


def _sello_zona(c, ancho, alto, lineas, stamp_rect):
    """Stamp placed inside a user-defined rectangle, Adobe-style."""
    x0, y0_mu, x1, y1_mu = stamp_rect
    rx = x0
    ry = alto - y1_mu
    rw = x1 - x0
    rh = y1_mu - y0_mu

    if rw < 10 or rh < 10:
        return

    pad = min(4 * mm, rw * 0.06, rh * 0.08)
    radius = min(2.5 * mm, rw / 6, rh / 6)

    c.setFillColor(BG_FILL)
    c.setStrokeColor(HexColor(ACCENT))
    c.setLineWidth(1.2)
    c.roundRect(rx, ry, rw, rh, radius, fill=1, stroke=1)

    lineas = [ln.upper() for ln in lineas]
    n = len(lineas)
    avail_h = rh - 2 * pad
    interlinea = min(6 * mm, avail_h / max(n + 0.3, 1))
    header_sz = min(12, max(8, interlinea / mm * 1.5))
    body_sz = min(10, max(7, header_sz * 0.78))

    tx = rx + pad
    ty = ry + rh - pad - header_sz * 0.4

    c.setFont('Helvetica-Bold', header_sz)
    c.setFillColor(HexColor(ACCENT))
    c.drawString(tx, ty, lineas[0])

    sep_y = ty - interlinea * 0.35
    c.setStrokeColor(HexColor(ACCENT))
    c.setLineWidth(0.8)
    c.line(tx, sep_y, rx + rw - pad, sep_y)

    ty = sep_y - interlinea * 0.65
    for ln in lineas[1:]:
        c.setFont('Helvetica-Bold', body_sz)
        c.setFillColor(TEXT_DARK)
        c.drawString(tx, ty, ln)
        ty -= interlinea


def _lineas_sello(firmante, cargo, centro):
    ls = ["DOCUMENTO FIRMADO DIGITALMENTE"]
    lf = f"Firmante: {firmante}"
    if cargo:
        lf += f" \u2013 {cargo}"
    ls.append(lf)
    if centro:
        ls.append(centro)
    ls.append(f"Fecha: {datetime.now().strftime('%d/%m/%Y  %H:%M:%S')}")
    return ls


# ── PDF processing ───────────────────────────────────────────────────────

def _page_dims(page):
    """Get page width and height robustly, falling back to A4."""
    for box_attr in ('cropbox', 'mediabox'):
        try:
            box = getattr(page, box_attr, None)
            if box is None:
                continue
            w = abs(float(box[2]) - float(box[0]))
            h = abs(float(box[3]) - float(box[1]))
            if w > 10 and h > 10:
                return w, h
        except Exception:
            continue
    return 595.28, 841.89  # A4 fallback


def _sanitizar_nombre(text):
    """Remove invalid filename characters and normalize whitespace."""
    text = ' '.join(text.split())
    for ch in r'\/:*?"<>|':
        text = text.replace(ch, '')
    text = text.strip('. ')
    if len(text) > 120:
        text = text[:120].strip()
    return text


def _normalizar_texto(texto):
    """Collapse any whitespace (newlines, tabs, multiple spaces) into single spaces."""
    return re.sub(r'\s+', ' ', texto).strip()


def _aplicar_patron(texto, patron):
    """Extract variable part from text using a pattern with {NOMBRE} placeholder."""
    if not patron or '{' not in patron:
        return texto
    texto_limpio = _normalizar_texto(texto)
    parts = re.split(r'\{[^}]+\}', patron)
    regex_str = ''
    for i, part in enumerate(parts):
        if part:
            words = part.split()
            regex_str += r'\s+'.join(re.escape(w) for w in words)
        if i < len(parts) - 1:
            regex_str += r'\s*(.+?)\s*'
    match = re.search(regex_str, texto_limpio, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return texto_limpio


def _aplicar_plantilla(plantilla, nombre_texto, nombre_original, pagina):
    """Apply filename template replacing {nombre}, {original}, {pagina}."""
    r = plantilla
    for tag in ('{nombre}', '{NOMBRE}'):
        r = r.replace(tag, nombre_texto or '')
    for tag in ('{original}', '{ORIGINAL}'):
        r = r.replace(tag, nombre_original)
    for tag in ('{pagina}', '{PAGINA}'):
        r = r.replace(tag, f'{pagina:04d}')
    return _sanitizar_nombre(r)


def _extraer_nombres_paginas(pdf_path, total_pages, text_rect=None,
                             patron=None):
    """Extract text from a region or full page for use as filename."""
    if not HAS_FITZ:
        return None
    if text_rect is None and not patron:
        return None
    rect = fitz.Rect(*text_rect) if text_rect else None
    doc = fitz.open(pdf_path)
    nombres = []
    for i in range(total_pages):
        page = doc[i]
        raw = (page.get_text("text", clip=rect).strip() if rect
               else page.get_text("text").strip())
        if patron:
            raw = _aplicar_patron(raw, patron)
        clean = _sanitizar_nombre(raw)
        nombres.append(clean if clean else None)
    doc.close()
    return nombres


# ── Zone selector dialog ─────────────────────────────────────────────────

class ZoneSelectorDialog:
    """Dialog to visually select a text region from the first PDF page."""

    def __init__(self, parent, pdf_path):
        self.result = None
        self._doc = fitz.open(pdf_path)
        page = self._doc[0]

        max_w, max_h = 560, 700
        self.scale = min(max_w / page.rect.width, max_h / page.rect.height)
        mat = fitz.Matrix(self.scale, self.scale)
        pix = page.get_pixmap(matrix=mat, alpha=False)

        self._dlg = tk.Toplevel(parent)
        self._dlg.title("Seleccionar zona de texto")
        self._dlg.resizable(False, False)
        self._dlg.transient(parent)
        self._dlg.grab_set()

        frm = ttk.Frame(self._dlg, padding=10)
        frm.pack(fill='both', expand=True)

        ttk.Label(
            frm, text="Dibuje un rectángulo sobre la zona de texto:",
            font=('Segoe UI', 9),
        ).pack(anchor='w', pady=(0, 5))

        self._photo = tk.PhotoImage(data=pix.tobytes("ppm"))
        self._canvas = tk.Canvas(
            frm, width=pix.width, height=pix.height,
            cursor='crosshair', bg='white')
        self._canvas.pack()
        self._canvas.create_image(0, 0, anchor='nw', image=self._photo)

        self._canvas.bind('<ButtonPress-1>', self._on_press)
        self._canvas.bind('<B1-Motion>', self._on_drag)
        self._canvas.bind('<ButtonRelease-1>', self._on_release)

        self._text_var = tk.StringVar(value="")
        ttk.Label(
            frm, textvariable=self._text_var,
            foreground='#333', font=('Segoe UI', 8),
            wraplength=pix.width,
        ).pack(anchor='w', pady=(8, 0))

        self._preview_var = tk.StringVar(value="")
        ttk.Label(
            frm, textvariable=self._preview_var,
            foreground='#888', font=('Segoe UI', 7),
            wraplength=pix.width,
        ).pack(anchor='w', pady=(2, 5))

        btn_frm = ttk.Frame(frm)
        btn_frm.pack(fill='x', pady=(5, 0))
        ttk.Button(btn_frm, text="Aceptar",
                   command=self._accept).pack(side='right', padx=(5, 0))
        ttk.Button(btn_frm, text="Cancelar",
                   command=self._cancel).pack(side='right')

        self._rect_id = None
        self._start_x = 0
        self._start_y = 0
        self._pdf_rect = None

        self._dlg.update_idletasks()
        dw = self._dlg.winfo_width()
        dh = self._dlg.winfo_height()
        x = (self._dlg.winfo_screenwidth() - dw) // 2
        y = (self._dlg.winfo_screenheight() - dh) // 2
        self._dlg.geometry(f"+{x}+{y}")

        self._dlg.wait_window()

    def _on_press(self, event):
        self._start_x = event.x
        self._start_y = event.y
        if self._rect_id:
            self._canvas.delete(self._rect_id)

    def _on_drag(self, event):
        if self._rect_id:
            self._canvas.delete(self._rect_id)
        self._rect_id = self._canvas.create_rectangle(
            self._start_x, self._start_y, event.x, event.y,
            outline='#e74c3c', width=2, dash=(5, 3))

    def _on_release(self, event):
        x0 = min(self._start_x, event.x) / self.scale
        y0 = min(self._start_y, event.y) / self.scale
        x1 = max(self._start_x, event.x) / self.scale
        y1 = max(self._start_y, event.y) / self.scale

        if abs(x1 - x0) < 5 or abs(y1 - y0) < 5:
            return

        self._pdf_rect = (x0, y0, x1, y1)
        rect = fitz.Rect(x0, y0, x1, y1)

        text = self._doc[0].get_text("text", clip=rect).strip()
        if text:
            self._text_var.set(f"Pág. 1: {text}")
        else:
            self._text_var.set(
                "(no se detectó texto en la zona seleccionada)")

        previews = []
        for p in range(1, min(4, len(self._doc))):
            t = self._doc[p].get_text("text", clip=rect).strip()
            if t:
                previews.append(f"Pág. {p + 1}: {t}")
        self._preview_var.set(
            " | ".join(previews) if previews else "")

    def _accept(self):
        self.result = self._pdf_rect
        self._doc.close()
        self._dlg.destroy()

    def _cancel(self):
        self.result = None
        self._doc.close()
        self._dlg.destroy()


class StampZoneSelectorDialog:
    """Dialog to select where to place the signature stamp on the page."""

    def __init__(self, parent, pdf_path):
        self.result = None
        self._doc = fitz.open(pdf_path)
        page = self._doc[0]

        max_w, max_h = 560, 700
        self.scale = min(max_w / page.rect.width, max_h / page.rect.height)
        mat = fitz.Matrix(self.scale, self.scale)
        pix = page.get_pixmap(matrix=mat, alpha=False)

        self._dlg = tk.Toplevel(parent)
        self._dlg.title("Seleccionar zona del sello")
        self._dlg.resizable(False, False)
        self._dlg.transient(parent)
        self._dlg.grab_set()

        frm = ttk.Frame(self._dlg, padding=10)
        frm.pack(fill='both', expand=True)

        ttk.Label(
            frm,
            text="Dibuje un rectángulo donde colocar el sello de firma:",
            font=('Segoe UI', 9),
        ).pack(anchor='w', pady=(0, 5))

        self._photo = tk.PhotoImage(data=pix.tobytes("ppm"))
        self._canvas = tk.Canvas(
            frm, width=pix.width, height=pix.height,
            cursor='crosshair', bg='white')
        self._canvas.pack()
        self._canvas.create_image(0, 0, anchor='nw', image=self._photo)

        self._canvas.bind('<ButtonPress-1>', self._on_press)
        self._canvas.bind('<B1-Motion>', self._on_drag)
        self._canvas.bind('<ButtonRelease-1>', self._on_release)

        self._info_var = tk.StringVar(value="")
        ttk.Label(
            frm, textvariable=self._info_var,
            foreground='#333', font=('Segoe UI', 8),
        ).pack(anchor='w', pady=(8, 5))

        btn_frm = ttk.Frame(frm)
        btn_frm.pack(fill='x', pady=(5, 0))
        ttk.Button(btn_frm, text="Aceptar",
                   command=self._accept).pack(side='right', padx=(5, 0))
        ttk.Button(btn_frm, text="Cancelar",
                   command=self._cancel).pack(side='right')

        self._rect_id = None
        self._start_x = 0
        self._start_y = 0
        self._pdf_rect = None

        self._dlg.update_idletasks()
        dw = self._dlg.winfo_width()
        dh = self._dlg.winfo_height()
        x = (self._dlg.winfo_screenwidth() - dw) // 2
        y = (self._dlg.winfo_screenheight() - dh) // 2
        self._dlg.geometry(f"+{x}+{y}")

        self._dlg.wait_window()

    def _on_press(self, event):
        self._start_x = event.x
        self._start_y = event.y
        if self._rect_id:
            self._canvas.delete(self._rect_id)

    def _on_drag(self, event):
        if self._rect_id:
            self._canvas.delete(self._rect_id)
        self._rect_id = self._canvas.create_rectangle(
            self._start_x, self._start_y, event.x, event.y,
            outline='#2980b9', width=2, fill='#aed6f1', stipple='gray50')

    def _on_release(self, event):
        x0 = min(self._start_x, event.x) / self.scale
        y0 = min(self._start_y, event.y) / self.scale
        x1 = max(self._start_x, event.x) / self.scale
        y1 = max(self._start_y, event.y) / self.scale

        if abs(x1 - x0) < 20 or abs(y1 - y0) < 15:
            return

        self._pdf_rect = (x0, y0, x1, y1)
        w_mm = (x1 - x0) * 25.4 / 72
        h_mm = (y1 - y0) * 25.4 / 72
        self._info_var.set(
            f"Zona seleccionada: {w_mm:.0f} x {h_mm:.0f} mm")

    def _accept(self):
        self.result = self._pdf_rect
        self._doc.close()
        self._dlg.destroy()

    def _cancel(self):
        self.result = None
        self._doc.close()
        self._dlg.destroy()


def separar_y_sellar(pdf_path, output_dir, firmante, cargo, centro,
                     posicion, text_rect=None, stamp_rect=None,
                     text_patron=None, nombre_plantilla=None,
                     callback=None):
    reader = PdfReader(pdf_path)
    if reader.is_encrypted:
        raise ValueError("El PDF está protegido. Desprotéjalo primero.")
    total = len(reader.pages)
    if total == 0:
        raise ValueError("El PDF no contiene páginas.")

    nombre = Path(pdf_path).stem
    lineas = _lineas_sello(firmante, cargo, centro)

    nombres_pag = _extraer_nombres_paginas(
        pdf_path, total, text_rect, text_patron)
    has_names = text_rect or text_patron
    plantilla = nombre_plantilla or (
        '{nombre}' if has_names else '{original}_p{pagina}')

    nombres_finales = []
    used = set()
    for i in range(total):
        texto = nombres_pag[i] if nombres_pag else None
        if texto:
            n = _aplicar_plantilla(plantilla, texto, nombre, i + 1)
        else:
            n = _aplicar_plantilla(
                '{original}_p{pagina}', None, nombre, i + 1)
        if not n:
            n = f"{nombre}_p{i + 1:04d}"
        original_n = n
        suffix = 2
        while n in used:
            n = f"{original_n} ({suffix})"
            suffix += 1
        used.add(n)
        nombres_finales.append(n)

    archivos = []
    for i in range(total):
        page = reader.pages[i]
        ancho, alto = _page_dims(page)

        overlay_buf = _crear_sello(ancho, alto, lineas, posicion, stamp_rect)
        overlay_reader = PdfReader(overlay_buf)
        page.merge_page(overlay_reader.pages[0])

        writer = PdfWriter()
        writer.add_page(page)
        out = os.path.join(output_dir, f"{nombres_finales[i]}.pdf")
        with open(out, 'wb') as f:
            writer.write(f)
        archivos.append(out)

        if callback:
            callback(i + 1, total,
                     f"Separando y sellando página {i + 1} de {total}\u2026")
    return archivos


def _crear_pdf_signer(signer_obj):
    meta = signers.PdfSignatureMetadata(
        field_name='Firma',
        reason='Documento firmado digitalmente',
        location='ES',
    )
    return signers.PdfSigner(
        signature_meta=meta,
        signer=signer_obj,
    )


def firmar_pdf(input_path, output_path, pdf_signer):
    with open(input_path, 'rb') as inf:
        w = IncrementalPdfFileWriter(inf)
        with open(output_path, 'wb') as outf:
            pdf_signer.sign_pdf(w, output=outf)


def cargar_certificado_pfx(pfx_path, password):
    passphrase = password.encode('utf-8') if password else None
    try:
        return signers.SimpleSigner.load_pkcs12(
            pfx_file=pfx_path, passphrase=passphrase,
        )
    except Exception as e:
        t = str(e).lower()
        if any(w in t for w in ('password', 'mac', 'decrypt', 'invalid')):
            raise ValueError("Contraseña incorrecta.") from e
        raise ValueError(f"Error al cargar certificado:\n{e}") from e


# ── GUI ──────────────────────────────────────────────────────────────────

class FirmadorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Firmador de PDFs \u2013 Certificado FNMT")
        self.root.geometry("680x750")
        self.root.resizable(False, False)
        self._center()

        self.pdf_var = tk.StringVar()
        self.cert_mode = tk.StringVar(
            value='store' if HAS_WIN_CERT_STORE else 'file')
        self.cert_var = tk.StringVar()
        self.pass_var = tk.StringVar()
        self.firmante_var = tk.StringVar()
        self.cargo_var = tk.StringVar()
        self.centro_var = tk.StringVar()
        self.output_var = tk.StringVar()
        self.posicion_var = tk.StringVar(value="inferior")
        self.status_var = tk.StringVar(value="Listo")
        self._processing = False

        self._win_session = None
        self._win_cert_label_var = tk.StringVar(value="(ninguno seleccionado)")

        self._text_rect = None
        self._zone_raw_text = ""
        self._page_full_text = None
        self._use_text_name = tk.BooleanVar(value=False)
        self._zone_text_var = tk.StringVar(value="")
        self._patron_var = tk.StringVar(value="")
        self._plantilla_var = tk.StringVar(value="{nombre}")
        self._preview_nombre_var = tk.StringVar(value="")

        self._stamp_rect = None
        self._stamp_zone_text_var = tk.StringVar(value="")

        self._build_ui()

    def _center(self):
        self.root.update_idletasks()
        w, h = 680, 750
        x = (self.root.winfo_screenwidth() - w) // 2
        y = (self.root.winfo_screenheight() - h) // 2
        self.root.geometry(f"{w}x{h}+{x}+{y}")

    def _build_ui(self):
        ttk.Style().configure('T.TLabel', font=('Segoe UI', 13, 'bold'))

        m = ttk.Frame(self.root, padding=15)
        m.pack(fill='both', expand=True)

        ttk.Label(m, text="Firmador de PDFs", style='T.TLabel').pack(anchor='w')
        ttk.Label(
            m, foreground='#666', font=('Segoe UI', 8),
            text="Separa, sella y firma digitalmente documentos PDF "
                 "con certificado FNMT",
        ).pack(anchor='w', pady=(0, 10))

        self._section_pdf(m)
        self._section_cert(m)
        self._section_sello(m)
        self._section_salida(m)

        self.btn = ttk.Button(
            m, text="\u270d  Firmar Documentos", command=self._start)
        self.btn.pack(fill='x', ipady=6, pady=(2, 0))

        self.progress = ttk.Progressbar(m, mode='determinate')
        self.progress.pack(fill='x', pady=(10, 3))
        ttk.Label(m, textvariable=self.status_var, foreground='#888') \
            .pack(anchor='w')

    # ── sections ─────────────────────────────────────────────────────

    def _section_pdf(self, parent):
        f = ttk.LabelFrame(parent, text=" Documento PDF ", padding=8)
        f.pack(fill='x', pady=(0, 6))
        r = ttk.Frame(f)
        r.pack(fill='x')
        ttk.Entry(r, textvariable=self.pdf_var) \
            .pack(side='left', fill='x', expand=True, padx=(0, 5))
        ttk.Button(r, text="Examinar\u2026", command=self._sel_pdf) \
            .pack(side='right')

        if HAS_FITZ:
            r2 = ttk.Frame(f)
            r2.pack(fill='x', pady=(5, 0))
            ttk.Checkbutton(
                r2, text="Nombre de archivo desde el PDF",
                variable=self._use_text_name,
                command=self._toggle_text_name,
            ).pack(side='left')

            self._name_controls = ttk.Frame(f)

            rz = ttk.Frame(self._name_controls)
            rz.pack(fill='x', pady=(3, 0))
            ttk.Button(
                rz, text="Seleccionar zona\u2026",
                command=self._sel_zone,
            ).pack(side='left')
            ttk.Label(
                rz, text="(opcional)",
                foreground='#888', font=('Segoe UI', 7),
            ).pack(side='left', padx=(5, 0))
            ttk.Label(
                rz, textvariable=self._zone_text_var,
                foreground='#444', font=('Segoe UI', 8),
            ).pack(side='left', padx=(5, 0))

            rp = ttk.Frame(self._name_controls)
            rp.pack(fill='x', pady=(3, 0))
            ttk.Label(rp, text="Buscar en frase (opcional):",
                      font=('Segoe UI', 8)).pack(side='left')
            ttk.Entry(rp, textvariable=self._patron_var, width=34) \
                .pack(side='left', padx=(5, 0), fill='x', expand=True)
            ttk.Label(
                self._name_controls,
                text="  Ejemplo: acreditamos que {NOMBRE} ha asistido al curso",
                foreground='#999', font=('Segoe UI', 7),
            ).pack(anchor='w')

            rt = ttk.Frame(self._name_controls)
            rt.pack(fill='x', pady=(3, 0))
            ttk.Label(rt, text="Nombre de archivo:",
                      font=('Segoe UI', 8)).pack(side='left')
            ttk.Entry(rt, textvariable=self._plantilla_var, width=36) \
                .pack(side='left', padx=(5, 0), fill='x', expand=True)
            ttk.Label(rt, text=".pdf", font=('Segoe UI', 8)) \
                .pack(side='left')

            ttk.Label(
                self._name_controls,
                textvariable=self._preview_nombre_var,
                foreground='#1a5276', font=('Segoe UI', 8, 'bold'),
            ).pack(anchor='w', pady=(3, 0))

            self._patron_var.trace_add('write', self._update_nombre_preview)
            self._plantilla_var.trace_add(
                'write', self._update_nombre_preview)

    def _section_cert(self, parent):
        f = ttk.LabelFrame(
            parent, text=" Certificado Digital ", padding=8)
        f.pack(fill='x', pady=(0, 6))

        if HAS_WIN_CERT_STORE:
            mode_row = ttk.Frame(f)
            mode_row.pack(fill='x', pady=(0, 6))
            ttk.Radiobutton(
                mode_row, text="Almacén de Windows",
                variable=self.cert_mode, value='store',
                command=self._toggle_cert,
            ).pack(side='left', padx=(0, 12))
            ttk.Radiobutton(
                mode_row, text="Archivo .pfx / .p12",
                variable=self.cert_mode, value='file',
                command=self._toggle_cert,
            ).pack(side='left')

        # Store mode frame
        self._frame_store = ttk.Frame(f)
        rs = ttk.Frame(self._frame_store)
        rs.pack(fill='x')
        ttk.Label(rs, textvariable=self._win_cert_label_var,
                  foreground='#444', font=('Segoe UI', 8)) \
            .pack(side='left', fill='x', expand=True)
        ttk.Button(rs, text="Seleccionar\u2026",
                   command=self._sel_win_cert).pack(side='right')

        # File mode frame
        self._frame_file = ttk.Frame(f)
        rf = ttk.Frame(self._frame_file)
        rf.pack(fill='x')
        ttk.Entry(rf, textvariable=self.cert_var) \
            .pack(side='left', fill='x', expand=True, padx=(0, 5))
        ttk.Button(rf, text="Examinar\u2026", command=self._sel_cert_file) \
            .pack(side='right')
        rf2 = ttk.Frame(self._frame_file)
        rf2.pack(fill='x', pady=(5, 0))
        ttk.Label(rf2, text="Contraseña:").pack(side='left')
        ttk.Entry(rf2, textvariable=self.pass_var, show='\u2022', width=28) \
            .pack(side='left', padx=5)

        self._toggle_cert()

    def _toggle_cert(self):
        if self.cert_mode.get() == 'store' and HAS_WIN_CERT_STORE:
            self._frame_file.pack_forget()
            self._frame_store.pack(fill='x')
        else:
            self._frame_store.pack_forget()
            self._frame_file.pack(fill='x')

    def _section_sello(self, parent):
        f = ttk.LabelFrame(parent, text=" Datos del Sello ", padding=8)
        f.pack(fill='x', pady=(0, 6))
        g = ttk.Frame(f)
        g.pack(fill='x')
        for i, (lbl, var) in enumerate([
            ("Firmante:", self.firmante_var),
            ("Cargo:", self.cargo_var),
            ("Organización:", self.centro_var),
        ]):
            ttk.Label(g, text=lbl).grid(row=i, column=0, sticky='w', pady=2)
            ttk.Entry(g, textvariable=var, width=52) \
                .grid(row=i, column=1, padx=5, pady=2, sticky='ew')
        g.columnconfigure(1, weight=1)

        rp = ttk.Frame(f)
        rp.pack(fill='x', pady=(5, 0))
        ttk.Label(rp, text="Posición del sello:").pack(side='left')
        ttk.Radiobutton(rp, text="Inferior",
                        variable=self.posicion_var, value='inferior',
                        command=self._toggle_stamp_pos) \
            .pack(side='left', padx=(10, 5))
        ttk.Radiobutton(rp, text="Lateral izquierdo",
                        variable=self.posicion_var, value='izquierda',
                        command=self._toggle_stamp_pos) \
            .pack(side='left')

        if HAS_FITZ:
            ttk.Radiobutton(
                rp, text="Zona personalizada",
                variable=self.posicion_var, value='zona',
                command=self._toggle_stamp_pos,
            ).pack(side='left', padx=(5, 0))

            self._stamp_zone_frame = ttk.Frame(f)
            r_sz = ttk.Frame(self._stamp_zone_frame)
            r_sz.pack(fill='x')
            ttk.Button(
                r_sz, text="Seleccionar zona del sello\u2026",
                command=self._sel_stamp_zone,
            ).pack(side='left')
            ttk.Label(
                r_sz, textvariable=self._stamp_zone_text_var,
                foreground='#444', font=('Segoe UI', 8),
            ).pack(side='left', padx=(8, 0))

    def _section_salida(self, parent):
        f = ttk.LabelFrame(parent, text=" Carpeta de Salida ", padding=8)
        f.pack(fill='x', pady=(0, 10))
        r = ttk.Frame(f)
        r.pack(fill='x')
        ttk.Entry(r, textvariable=self.output_var) \
            .pack(side='left', fill='x', expand=True, padx=(0, 5))
        ttk.Button(r, text="Examinar\u2026", command=self._sel_output) \
            .pack(side='right')

    # ── selectors ────────────────────────────────────────────────────

    def _sel_pdf(self):
        p = filedialog.askopenfilename(
            title="Seleccionar PDF",
            filetypes=[("PDF", "*.pdf"), ("Todos", "*.*")])
        if p:
            self.pdf_var.set(p)
            if not self.output_var.get():
                self.output_var.set(
                    str(Path(p).parent / f"{Path(p).stem}_firmados"))
            self._reset_zone()

    def _sel_cert_file(self):
        p = filedialog.askopenfilename(
            title="Seleccionar certificado",
            filetypes=[("PKCS#12", "*.pfx *.p12"), ("Todos", "*.*")])
        if p:
            self.cert_var.set(p)

    def _sel_win_cert(self):
        try:
            hwnd = self.root.winfo_id()
        except Exception:
            hwnd = None
        try:
            session = WinCertSession()
            if session.select(hwnd):
                if self._win_session:
                    self._win_session.close()
                self._win_session = session
                self._win_cert_label_var.set(session.subject)
            else:
                session.close()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _sel_output(self):
        p = filedialog.askdirectory(title="Carpeta de salida")
        if p:
            self.output_var.set(p)

    # ── text zone ─────────────────────────────────────────────────────

    def _get_page_text(self):
        """Full text of page 1, cached for preview."""
        if self._page_full_text is not None:
            return self._page_full_text
        pdf = self.pdf_var.get()
        if not pdf or not os.path.isfile(pdf) or not HAS_FITZ:
            return ""
        try:
            doc = fitz.open(pdf)
            self._page_full_text = doc[0].get_text("text").strip()
            doc.close()
        except Exception:
            self._page_full_text = ""
        return self._page_full_text

    def _update_nombre_preview(self, *_):
        patron = self._patron_var.get().strip()
        plantilla = self._plantilla_var.get().strip() or '{nombre}'
        if self._zone_raw_text:
            texto = self._zone_raw_text
            if patron:
                texto = _aplicar_patron(texto, patron)
            texto = _sanitizar_nombre(texto)
        elif patron:
            page_text = self._get_page_text()
            if not page_text:
                self._preview_nombre_var.set("")
                return
            texto = _aplicar_patron(page_text, patron)
            texto = _sanitizar_nombre(texto)
        else:
            self._preview_nombre_var.set("")
            return
        ejemplo = plantilla.replace('{nombre}', texto or '?')
        ejemplo = ejemplo.replace('{NOMBRE}', texto or '?')
        ejemplo = _sanitizar_nombre(ejemplo)
        if ejemplo:
            self._preview_nombre_var.set(f"\u2192 {ejemplo}.pdf")
        else:
            self._preview_nombre_var.set("(sin resultado)")

    def _toggle_text_name(self):
        if not HAS_FITZ:
            return
        if self._use_text_name.get():
            self._name_controls.pack(fill='x')
            self._update_nombre_preview()
        else:
            self._name_controls.pack_forget()
            self._text_rect = None
            self._zone_raw_text = ""
            self._page_full_text = None
            self._zone_text_var.set("")
            self._preview_nombre_var.set("")

    def _sel_zone(self):
        pdf = self.pdf_var.get()
        if not pdf or not os.path.isfile(pdf):
            messagebox.showwarning(
                "Atención", "Seleccione primero un archivo PDF.")
            return
        try:
            dlg = ZoneSelectorDialog(self.root, pdf)
            if dlg.result:
                self._text_rect = dlg.result
                doc = fitz.open(pdf)
                raw = doc[0].get_text(
                    "text", clip=fitz.Rect(*dlg.result)).strip()
                doc.close()
                self._zone_raw_text = raw
                preview = raw[:60] + ('\u2026' if len(raw) > 60 else '')
                self._zone_text_var.set(
                    f"\u2192 \"{preview}\"" if raw
                    else "(sin texto en la zona)")
                self._update_nombre_preview()
        except Exception as e:
            messagebox.showerror(
                "Error", f"No se pudo abrir el PDF:\n{e}")

    def _toggle_stamp_pos(self):
        if not HAS_FITZ or not hasattr(self, '_stamp_zone_frame'):
            return
        if self.posicion_var.get() == 'zona':
            self._stamp_zone_frame.pack(fill='x', pady=(5, 0))
        else:
            self._stamp_zone_frame.pack_forget()
            self._stamp_rect = None
            self._stamp_zone_text_var.set("")

    def _sel_stamp_zone(self):
        pdf = self.pdf_var.get()
        if not pdf or not os.path.isfile(pdf):
            messagebox.showwarning(
                "Atención", "Seleccione primero un archivo PDF.")
            return
        try:
            dlg = StampZoneSelectorDialog(self.root, pdf)
            if dlg.result:
                self._stamp_rect = dlg.result
                w_mm = (dlg.result[2] - dlg.result[0]) * 25.4 / 72
                h_mm = (dlg.result[3] - dlg.result[1]) * 25.4 / 72
                self._stamp_zone_text_var.set(
                    f"Zona: {w_mm:.0f} x {h_mm:.0f} mm")
        except Exception as e:
            messagebox.showerror(
                "Error", f"No se pudo abrir el PDF:\n{e}")

    def _reset_zone(self):
        self._text_rect = None
        self._zone_raw_text = ""
        self._page_full_text = None
        self._stamp_rect = None
        if HAS_FITZ:
            self._zone_text_var.set("")
            self._preview_nombre_var.set("")
            self._stamp_zone_text_var.set("")
            if hasattr(self, '_name_controls'):
                self._name_controls.pack_forget()
            self._use_text_name.set(False)

    # ── validation & processing ──────────────────────────────────────

    def _validate(self):
        if not self.pdf_var.get():
            messagebox.showwarning("Atención", "Seleccione un archivo PDF.")
            return False
        if not os.path.isfile(self.pdf_var.get()):
            messagebox.showerror("Error", "El archivo PDF no existe.")
            return False

        if self.cert_mode.get() == 'file':
            if not self.cert_var.get():
                messagebox.showwarning(
                    "Atención", "Seleccione un certificado (.pfx/.p12).")
                return False
            if not os.path.isfile(self.cert_var.get()):
                messagebox.showerror(
                    "Error", "El archivo de certificado no existe.")
                return False
        else:
            if not self._win_session or not self._win_session.cert_der:
                messagebox.showwarning(
                    "Atención",
                    "Seleccione un certificado del almacén de Windows.")
                return False

        if (self.posicion_var.get() == 'zona'
                and not self._stamp_rect):
            messagebox.showwarning(
                "Atención",
                "Seleccione la zona donde colocar el sello de firma.")
            return False

        if not self.firmante_var.get().strip():
            messagebox.showwarning(
                "Atención", "Introduzca el nombre del firmante.")
            return False
        if not self.output_var.get():
            messagebox.showwarning(
                "Atención", "Seleccione una carpeta de salida.")
            return False
        return True

    def _start(self):
        if self._processing or not self._validate():
            return
        self._processing = True
        self.btn.configure(state='disabled')
        self.progress['value'] = 0
        threading.Thread(target=self._process, daemon=True).start()

    def _prog(self, cur, tot, msg):
        def _ui():
            self.progress['value'] = (cur / max(tot, 1)) * 100
            self.status_var.set(msg)
        self.root.after(0, _ui)

    def _process(self):
        try:
            out_dir = self.output_var.get()
            os.makedirs(out_dir, exist_ok=True)

            self._prog(0, 1, "Cargando certificado digital\u2026")
            if self.cert_mode.get() == 'file':
                signer_obj = cargar_certificado_pfx(
                    self.cert_var.get(), self.pass_var.get())
            else:
                signer_obj = WindowsSigner(self._win_session)

            pdf_signer = _crear_pdf_signer(signer_obj)

            use_text = self._use_text_name.get()
            text_rect = self._text_rect if use_text else None
            text_patron = (self._patron_var.get().strip()
                           if use_text else None)
            nombre_plantilla = (self._plantilla_var.get().strip()
                                if use_text else None)
            stamp_rect = (self._stamp_rect
                          if self.posicion_var.get() == 'zona' else None)
            archivos = separar_y_sellar(
                self.pdf_var.get(), out_dir,
                self.firmante_var.get().strip(),
                self.cargo_var.get().strip(),
                self.centro_var.get().strip(),
                self.posicion_var.get(),
                text_rect=text_rect,
                stamp_rect=stamp_rect,
                text_patron=text_patron,
                nombre_plantilla=nombre_plantilla,
                callback=lambda c, t, m: self._prog(c, t * 2, m),
            )

            total = len(archivos)
            for i, fpath in enumerate(archivos):
                self._prog(total + i + 1, total * 2,
                           f"Firmando digitalmente {i + 1} de {total}\u2026")
                tmp = fpath + '.tmp'
                firmar_pdf(fpath, tmp, pdf_signer)
                os.replace(tmp, fpath)

            self._prog(1, 1, f"Completado: {total} documentos firmados")
            self.root.after(0, lambda: messagebox.showinfo(
                "Completado",
                f"{total} documentos firmados.\n\nCarpeta:\n{out_dir}",
            ))
        except Exception as e:
            self._prog(0, 1, f"Error: {e}")
            self.root.after(0, lambda e=e: messagebox.showerror(
                "Error", str(e)))
        finally:
            self._processing = False
            self.root.after(0, lambda: self.btn.configure(state='normal'))


# ── Entry point ──────────────────────────────────────────────────────────

def main():
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    root = tk.Tk()
    FirmadorApp(root)
    root.mainloop()


if __name__ == '__main__':
    main()
