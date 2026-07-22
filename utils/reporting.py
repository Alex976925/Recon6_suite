"""
Generador de PDF con el mismo lenguaje visual del dashboard (fondo oscuro,
acento amarillo, tarjetas KPI) y gráficas dibujadas de verdad (radar, barras
de distribución de tecnología, línea de riesgo histórico) usando las
primitivas de dibujo nativas de fpdf2 — sin matplotlib ni ninguna
dependencia pesada nueva, para que siga instalando bien en Termux/Android.
"""

import math
import os
from datetime import datetime
from fpdf import FPDF

REPORTS_DIR = "reportes"

# Paleta — igual a static/css/style.css
BG = (11, 15, 20)
SURFACE = (17, 24, 39)
BORDER = (31, 41, 55)
ACCENT = (250, 204, 21)
TEXT_PRIMARY = (249, 250, 251)
TEXT_SECONDARY = (156, 163, 175)
SEV_LOW = (34, 197, 94)
SEV_MED = (245, 158, 11)
SEV_HIGH = (239, 68, 68)
CAT_COLORS = [(250, 204, 21), (56, 189, 248), (167, 139, 250), (52, 211, 153), (248, 113, 113), (156, 163, 175)]

_REEMPLAZOS_UNICODE = {
    "✅": "[OK]", "❌": "[X]", "⚠": "[!]", "🛰": "", "🦠": "", "📧": "", "🔎": "", "📸": "",
    "●": "-", "•": "-", "…": "...", "—": "-", "–": "-",
    "'": "'", "'": "'", """: '"', """: '"',
}


def _sanitizar(texto):
    if not texto:
        return ""
    for original, reemplazo in _REEMPLAZOS_UNICODE.items():
        texto = texto.replace(original, reemplazo)
    return texto.encode("latin-1", errors="replace").decode("latin-1")


class ReconPDF(FPDF):
    def header(self):
        # Fondo oscuro en toda la página
        self.set_fill_color(*BG)
        self.rect(0, 0, self.w, self.h, style="F")
        # Barra superior
        self.set_xy(10, 10)
        self.set_font("Helvetica", "B", 15)
        self.set_text_color(*ACCENT)
        self.cell(0, 8, "RECON6_SUITE", ln=True)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*TEXT_SECONDARY)
        self.cell(0, 5, f"Enterprise Recon Report  -  Generado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
        self.set_draw_color(*BORDER)
        self.set_line_width(0.3)
        self.line(10, self.get_y() + 2, self.w - 10, self.get_y() + 2)
        self.ln(6)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 7)
        self.set_text_color(*TEXT_SECONDARY)
        self.cell(0, 10, f"Pagina {self.page_no()} - Uso interno / laboratorio", align="C")

    # ---------- helpers de layout ----------
    def seccion(self, titulo):
        if self.get_y() > self.h - 30:
            self.add_page()
        self.ln(2)
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(*TEXT_PRIMARY)
        self.cell(0, 8, _sanitizar(titulo), ln=True)
        self.set_draw_color(*BORDER)
        self.line(10, self.get_y(), self.w - 10, self.get_y())
        self.ln(3)

    def texto_mono(self, texto, size=8.5, color=TEXT_PRIMARY):
        self.set_font("Courier", "", size)
        self.set_text_color(*color)
        self.multi_cell(0, 4.2, _sanitizar(texto) or "(sin datos)")
        self.ln(1)

    def panel_inicio(self, alto):
        """Dibuja el fondo de una 'tarjeta' tipo panel del dashboard y
        devuelve las coordenadas donde empieza el contenido."""
        x, y = 10, self.get_y()
        w = self.w - 20
        if y + alto > self.h - 20:
            self.add_page()
            x, y = 10, self.get_y()
        self.set_fill_color(*SURFACE)
        self.set_draw_color(*BORDER)
        self.rect(x, y, w, alto, style="DF", round_corners=True, corner_radius=2.5)
        return x, y, w

    # ---------- KPI cards ----------
    def kpi_cards(self, kpis):
        etiquetas = [
            ("Puertos abiertos", kpis.get("open_ports", 0), ""),
            ("Subdominios", kpis.get("subdomains", 0), ""),
            ("Tecnologias", kpis.get("technologies", 0), ""),
            ("Correos publicos", kpis.get("emails", 0), ""),
            ("Risk Score", kpis.get("risk_score", 0), "/100"),
        ]
        x0, y0 = 10, self.get_y()
        w = (self.w - 20 - 4 * 4) / 5
        h = 24
        for i, (label, valor, sufijo) in enumerate(etiquetas):
            x = x0 + i * (w + 4)
            self.set_xy(x, y0)
            self.set_fill_color(*SURFACE)
            self.set_draw_color(*BORDER)
            self.rect(x, y0, w, h, style="DF", round_corners=True, corner_radius=2)
            self.set_xy(x + 2, y0 + 3)
            self.set_font("Helvetica", "B", 15)
            self.set_text_color(*ACCENT)
            self.cell(w - 4, 8, f"{valor}{sufijo}", ln=False)
            self.set_xy(x + 2, y0 + 14)
            self.set_font("Helvetica", "", 6.8)
            self.set_text_color(*TEXT_SECONDARY)
            self.multi_cell(w - 4, 3.2, label)
        self.set_xy(x0, y0 + h + 5)

    # ---------- Radar chart (dibujado a mano, sin matplotlib) ----------
    def radar_chart(self, radar_dict, size=68):
        dims = list(radar_dict.items())
        n = len(dims)
        if n < 3:
            self.texto_mono("Datos insuficientes para radar.")
            return
        x, y, w = self.panel_inicio(size + 32)
        self.set_xy(x + 4, y + 4)
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(*TEXT_PRIMARY)
        self.cell(0, 6, "Attack Surface", ln=True)

        cx, cy = x + w * 0.32, y + size * 0.62
        R = size * 0.34

        def punto(i, frac):
            ang = -math.pi / 2 + i * (2 * math.pi / n)
            return cx + R * frac * math.cos(ang), cy + R * frac * math.sin(ang)

        # anillos de fondo
        self.set_draw_color(*BORDER)
        self.set_line_width(0.2)
        for frac in (0.33, 0.66, 1.0):
            pts = [punto(i, frac) for i in range(n)]
            self.polygon(pts, style="D")

        # ejes
        for i in range(n):
            px, py = punto(i, 1.0)
            self.line(cx, cy, px, py)

        # polígono de valores
        vpts = [punto(i, max(0.03, val / 100)) for i, (_, val) in enumerate(dims)]
        self.set_draw_color(*ACCENT)
        self.set_line_width(0.6)
        with self.local_context(fill_opacity=0.30):
            self.set_fill_color(*ACCENT)
            self.polygon(vpts, style="DF")

        # etiquetas
        self.set_font("Helvetica", "", 6.3)
        self.set_text_color(*TEXT_SECONDARY)
        for i, (label, val) in enumerate(dims):
            lx, ly = punto(i, 1.28)
            ancho_txt = 24
            self.set_xy(lx - ancho_txt / 2, ly - 2)
            self.multi_cell(ancho_txt, 2.6, f"{label}\n{val}", align="C")

        self.set_xy(x, y + size + 30)

    # ---------- Barras: distribución de tecnología ----------
    def barras_tech(self, doughnut_dict, alto=52):
        entradas = [(k, v) for k, v in doughnut_dict.items() if v > 0]
        x, y, w = self.panel_inicio(alto)
        self.set_xy(x + 4, y + 4)
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(*TEXT_PRIMARY)
        self.cell(0, 6, "Technology Distribution", ln=True)

        if not entradas:
            self.set_xy(x + 4, y + 16)
            self.set_font("Helvetica", "", 8)
            self.set_text_color(*TEXT_SECONDARY)
            self.cell(0, 5, "Sin tecnologias detectadas todavia.")
            self.set_xy(x, y + alto + 5)
            return

        maximo = max(v for _, v in entradas)
        bar_x = x + 40
        bar_max_w = w - 55
        by = y + 15
        for i, (cat, val) in enumerate(entradas):
            color = CAT_COLORS[i % len(CAT_COLORS)]
            self.set_xy(x + 4, by)
            self.set_font("Helvetica", "", 7.5)
            self.set_text_color(*TEXT_SECONDARY)
            self.cell(34, 5, cat, ln=False)
            ancho = max(2, (val / maximo) * bar_max_w)
            self.set_fill_color(*color)
            self.rect(bar_x, by, ancho, 4, style="F", round_corners=True, corner_radius=1)
            self.set_xy(bar_x + ancho + 2, by - 0.5)
            self.set_font("Helvetica", "B", 7)
            self.set_text_color(*TEXT_PRIMARY)
            self.cell(10, 5, str(val))
            by += 7
        self.set_xy(x, y + alto + 5)

    # ---------- Línea: historial de riesgo ----------
    def linea_riesgo(self, history, alto=46):
        x, y, w = self.panel_inicio(alto)
        self.set_xy(x + 4, y + 4)
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(*TEXT_PRIMARY)
        self.cell(0, 6, "Historical Risk Score", ln=True)

        gx, gy = x + 14, y + 12
        gw, gh = w - 24, alto - 22

        self.set_draw_color(*BORDER)
        self.set_line_width(0.2)
        for frac in (0, 0.25, 0.5, 0.75, 1.0):
            ly = gy + gh - frac * gh
            self.line(gx, ly, gx + gw, ly)
            self.set_xy(x, ly - 2)
            self.set_font("Helvetica", "", 5.5)
            self.set_text_color(*TEXT_SECONDARY)
            self.cell(12, 4, str(int(frac * 100)), align="R")

        if not history:
            self.set_xy(gx, gy + gh / 2 - 2)
            self.set_font("Helvetica", "", 7.5)
            self.set_text_color(*TEXT_SECONDARY)
            self.cell(gw, 4, "Sin historial todavia. Se llena con cada escaneo.", align="C")
            self.set_xy(x, y + alto + 5)
            return

        valores = [h.get("risk_score", 0) for h in history]
        n = len(valores)
        paso = gw / max(1, n - 1) if n > 1 else 0
        pts = []
        for i, val in enumerate(valores):
            px = gx + i * paso
            py = gy + gh - (val / 100) * gh
            pts.append((px, py))

        self.set_draw_color(*ACCENT)
        self.set_line_width(0.7)
        if len(pts) > 1:
            self.polyline(pts)
        for px, py in pts:
            self.set_fill_color(*ACCENT)
            self.ellipse(px - 1, py - 1, 2, 2, style="F")

        self.set_xy(x, y + alto + 5)

    # ---------- Tabla técnica con badges de severidad ----------
    def tabla_tecnica(self, filas, max_filas=40):
        if not filas:
            self.set_font("Helvetica", "", 8.5)
            self.set_text_color(*TEXT_SECONDARY)
            self.cell(0, 6, "Sin activos en el inventario todavia.", ln=True)
            return

        col_w = [38, 20, 16, 26, 40, 22]
        headers = ["Host", "Puerto", "Estado", "Severidad", "Tecnologia", "Servicio"]

        def fila_header():
            self.set_font("Helvetica", "B", 7.5)
            self.set_fill_color(*SURFACE)
            self.set_text_color(*TEXT_SECONDARY)
            self.set_draw_color(*BORDER)
            x0 = self.get_x()
            for w, h in zip(col_w, headers):
                self.cell(w, 6, h, border=0, fill=True)
            self.ln(6)

        fila_header()
        sev_color = {"low": SEV_LOW, "medium": SEV_MED, "high": SEV_HIGH}
        for i, row in enumerate(filas[:max_filas]):
            if self.get_y() > self.h - 20:
                self.add_page()
                fila_header()
            self.set_font("Helvetica", "", 7.3)
            self.set_text_color(*TEXT_PRIMARY)
            y0 = self.get_y()
            x0 = self.get_x()
            self.cell(col_w[0], 5.5, _sanitizar(str(row.get("host", "-")))[:26])
            self.cell(col_w[1], 5.5, str(row.get("port", "-")))
            self.cell(col_w[2], 5.5, _sanitizar(str(row.get("state", "-")))[:12])
            sev = row.get("severity", "medium")
            color = sev_color.get(sev, SEV_MED)
            self.set_fill_color(*color)
            badge_x = self.get_x() + 1
            self.rect(badge_x, y0 + 1, 16, 3.6, style="F", round_corners=True, corner_radius=1)
            self.set_xy(badge_x + 17, y0)
            self.set_text_color(*TEXT_SECONDARY)
            self.cell(col_w[3] - 17, 5.5, sev)
            self.set_text_color(*TEXT_PRIMARY)
            self.cell(col_w[4], 5.5, _sanitizar(str(row.get("technology", "-")))[:20])
            self.cell(col_w[5], 5.5, _sanitizar(str(row.get("service", "-")))[:16])
            self.ln(5.5)
        if len(filas) > max_filas:
            self.set_font("Helvetica", "I", 7)
            self.set_text_color(*TEXT_SECONDARY)
            self.cell(0, 5, f"... y {len(filas) - max_filas} activo(s) mas (ver dashboard para el listado completo).", ln=True)


def generar_pdf(target, resumen, scans_raw=None, diff_texto=None):
    scans_raw = scans_raw or {}
    os.makedirs(REPORTS_DIR, exist_ok=True)

    pdf = ReconPDF()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(*TEXT_PRIMARY)
    pdf.cell(0, 8, f"Objetivo: {_sanitizar(target)}", ln=True)
    pdf.ln(2)

    k = resumen.get("kpis", {})
    pdf.seccion("Resumen ejecutivo")
    pdf.kpi_cards(k)

    extra = []
    if k.get("ssl_days_left") is not None:
        extra.append(f"Dias restantes de certificado SSL: {k['ssl_days_left']}")
    if k.get("header_score") is not None:
        extra.append(f"Header Security Score: {k['header_score']}/100")
    if k.get("takeover_vulnerable"):
        extra.append(f"[!] Subdominios vulnerables a takeover: {k['takeover_vulnerable']}")
    if extra:
        pdf.set_font("Helvetica", "", 8.5)
        pdf.set_text_color(*TEXT_SECONDARY)
        for linea in extra:
            pdf.cell(0, 5, _sanitizar(linea), ln=True)
        pdf.ln(2)

    pdf.seccion("Attack Surface & Tecnologia")
    pdf.radar_chart(resumen.get("radar", {}))
    pdf.barras_tech(resumen.get("doughnut", {}))

    pdf.seccion("Historial de Risk Score")
    pdf.linea_riesgo(resumen.get("history", []))

    pdf.seccion(f"Inventario tecnico ({len(resumen.get('table', []))} activos)")
    pdf.tabla_tecnica(resumen.get("table", []))

    etiquetas_modulos = [
        ("whois", "WHOIS"), ("dns", "DNS"), ("nmap", "Nmap"), ("nmap_prof", "Nmap (Deep Scan)"),
        ("subdom", "Subdominios"), ("correos", "Correos"), ("tech", "Tecnologias"),
        ("ssl", "SSL/TLS"), ("headers", "Security Headers"), ("robots", "Robots/Sitemap"),
        ("takeover", "Subdomain Takeover"), ("cve", "CVEs"),
    ]
    modulos_con_datos = [(op, et) for op, et in etiquetas_modulos if scans_raw.get(op)]
    if modulos_con_datos:
        pdf.add_page()
        pdf.seccion("Detalle por modulo")
        for opcion, etiqueta in modulos_con_datos:
            data = scans_raw.get(opcion)
            if pdf.get_y() > pdf.h - 40:
                pdf.add_page()
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(*ACCENT)
            pdf.cell(0, 6, etiqueta, ln=True)
            pdf.texto_mono(str(data.get("resultado", ""))[:4000], size=7.6)
            pdf.ln(1)

    if diff_texto:
        pdf.add_page()
        pdf.seccion("Cambios detectados desde el escaneo anterior")
        pdf.texto_mono(diff_texto[:6000], size=7.8)

    nombre = f"{target.replace('.', '_').replace(':', '_')}_{datetime.now().strftime('%Y-%m-%d_%H%M')}.pdf"
    ruta = os.path.join(REPORTS_DIR, nombre)
    pdf.output(ruta)
    return ruta
