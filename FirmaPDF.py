"""
FirmaPDF v1.1
Utilidad para separar, sellar y firmar digitalmente documentos PDF
con certificado digital FNMT (.pfx/.p12 o almacén de Windows).

Uso: python FirmaPDF.py
Empaquetado: pyinstaller --onefile --windowed FirmaPDF.py
"""

import os
import sys
import io
import hashlib
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from datetime import datetime
from pathlib import Path


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

def _crear_sello(ancho, alto, lineas, posicion):
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(ancho, alto))
    if posicion == 'inferior':
        _sello_inferior(c, ancho, alto, lineas)
    else:
        _sello_izquierda(c, ancho, alto, lineas)
    c.save()
    buf.seek(0)
    return buf


def _sello_inferior(c, ancho, alto, lineas):
    margen_h = min(15 * mm, ancho * 0.05)
    margen_v = min(8 * mm, alto * 0.02)
    interlinea = 3.5 * mm
    pad = 3 * mm

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
    ty = margen_v + box_h - pad - 2 * mm
    for i, ln in enumerate(lineas):
        if i == 0:
            c.setFont('Helvetica-Bold', 7)
            c.setFillColor(HexColor(ACCENT))
        else:
            c.setFont('Helvetica', 6.5)
            c.setFillColor(TEXT_DARK)
        c.drawString(tx, ty - i * interlinea, ln)


def _sello_izquierda(c, ancho, alto, lineas):
    margen = min(6 * mm, ancho * 0.02)
    interlinea = 3 * mm
    pad = 2.5 * mm

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
            c.setFont('Helvetica-Bold', 6.5)
            c.setFillColor(HexColor(ACCENT))
        else:
            c.setFont('Helvetica', 6)
            c.setFillColor(TEXT_DARK)
        c.drawCentredString(0, -i * interlinea, ln)
    c.restoreState()


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


def separar_y_sellar(pdf_path, output_dir, firmante, cargo, centro,
                     posicion, callback=None):
    reader = PdfReader(pdf_path)
    if reader.is_encrypted:
        raise ValueError("El PDF está protegido. Desprotéjalo primero.")
    total = len(reader.pages)
    if total == 0:
        raise ValueError("El PDF no contiene páginas.")

    nombre = Path(pdf_path).stem
    lineas = _lineas_sello(firmante, cargo, centro)
    archivos = []

    for i in range(total):
        page = reader.pages[i]
        ancho, alto = _page_dims(page)

        overlay_buf = _crear_sello(ancho, alto, lineas, posicion)
        overlay_reader = PdfReader(overlay_buf)
        page.merge_page(overlay_reader.pages[0])

        writer = PdfWriter()
        writer.add_page(page)
        out = os.path.join(output_dir, f"{nombre}_p{i + 1:04d}.pdf")
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
        self.root.geometry("680x640")
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

        self._build_ui()

    def _center(self):
        self.root.update_idletasks()
        w, h = 680, 640
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
                        variable=self.posicion_var, value='inferior') \
            .pack(side='left', padx=(10, 5))
        ttk.Radiobutton(rp, text="Lateral izquierdo",
                        variable=self.posicion_var, value='izquierda') \
            .pack(side='left')

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

            archivos = separar_y_sellar(
                self.pdf_var.get(), out_dir,
                self.firmante_var.get().strip(),
                self.cargo_var.get().strip(),
                self.centro_var.get().strip(),
                self.posicion_var.get(),
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
