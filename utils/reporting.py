"""
Genera un reporte PDF real (no HTML disfrazado) a partir del resumen ya
calculado por utils.analytics, usando fpdf2 (dependencia ligera, sin
motor de renderizado de navegador).
"""

import os
from datetime import datetime
from fpdf import FPDF

REPORTS_DIR = "reportes"

_REEMPLAZOS_UNICODE = {
    "✅": "[OK]", "❌": "[X]", "⚠": "[!]", "🛰": "", "🦠": "", "📧": "", "🔎": "",
    "●": "-", "•": "-", "…": "...", "—": "-", "–": "-",
    "'": "'", "'": "'", """: '"', """: '"',
}


def _sanitizar(texto):
    """Reemplaza símbolos Unicode comunes por equivalentes ASCII y elimina
    cualquier carácter que las fuentes core de fpdf2 (latin-1) no puedan
    codificar, para evitar UnicodeEncodeError al generar el PDF."""
    if not texto:
        return ""
    for original, reemplazo in _REEMPLAZOS_UNICODE.items():
        texto = texto.replace(original, reemplazo)
    return texto.encode("latin-1", errors="replace").decode("latin-1")


class _ReconPDF(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(20, 20, 20)
        self.cell(0, 10, "Recon6_Suite - Reporte de Reconocimiento", ln=True)
        self.set_font("Helvetica", "", 9)
        self.set_text_color(100, 100, 100)
        self.cell(0, 6, f"Generado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
        self.ln(2)
        self.set_draw_color(200, 200, 200)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, f"Página {self.page_no()} - Uso interno / laboratorio", align="C")

    def seccion(self, titulo):
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(20, 20, 20)
        self.ln(3)
        self.cell(0, 8, _sanitizar(titulo), ln=True)
        self.set_draw_color(230, 230, 230)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(2)

    def cuerpo(self, texto, size=9):
        self.set_font("Courier", "", size)
        self.set_text_color(40, 40, 40)
        texto = _sanitizar(texto) or "(sin datos)"
        # fpdf2 no rompe líneas largas automáticamente en Courier con multi_cell si se limita el ancho
        self.multi_cell(0, 4.2, texto)
        self.ln(1)


def generar_pdf(target, resumen, scans_raw=None, diff_texto=None):
    scans_raw = scans_raw or {}
    os.makedirs(REPORTS_DIR, exist_ok=True)

    pdf = _ReconPDF()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 8, f"Objetivo: {target}", ln=True)
    pdf.ln(2)

    k = resumen.get("kpis", {})
    pdf.seccion("Resumen ejecutivo (KPIs)")
    kpi_lineas = [
        f"Puertos abiertos: {k.get('open_ports', 0)}",
        f"Subdominios encontrados: {k.get('subdomains', 0)}",
        f"Tecnologias detectadas: {k.get('technologies', 0)}",
        f"Correos publicos expuestos: {k.get('emails', 0)}",
        f"Risk Score: {k.get('risk_score', 0)}/100",
    ]
    if k.get("ssl_days_left") is not None:
        kpi_lineas.append(f"Dias restantes de certificado SSL: {k['ssl_days_left']}")
    if k.get("header_score") is not None:
        kpi_lineas.append(f"Header Security Score: {k['header_score']}/100")
    if k.get("takeover_vulnerable"):
        kpi_lineas.append(f"⚠ Subdominios vulnerables a takeover: {k['takeover_vulnerable']}")
    pdf.cuerpo("\n".join(kpi_lineas))

    pdf.seccion("Attack Surface (radar)")
    pdf.cuerpo("\n".join(f"{dim}: {val}/100" for dim, val in resumen.get("radar", {}).items()))

    tabla = resumen.get("table", [])
    if tabla:
        pdf.seccion(f"Inventario tecnico ({len(tabla)} activos)")
        for row in tabla[:60]:
            linea = (f"{row.get('host','-'):<30} puerto={row.get('port','-'):<6} "
                     f"servicio={row.get('service','-'):<15} sev={row.get('severity','-')}")
            pdf.cuerpo(linea, size=8)

    for opcion, etiqueta in [
        ("whois", "WHOIS"), ("dns", "DNS"), ("nmap", "Nmap"), ("nmap_prof", "Nmap (Deep Scan)"),
        ("subdom", "Subdominios"), ("correos", "Correos"), ("tech", "Tecnologias"),
        ("ssl", "SSL/TLS"), ("headers", "Security Headers"), ("robots", "Robots/Sitemap"),
        ("takeover", "Subdomain Takeover"), ("cve", "CVEs"),
    ]:
        data = scans_raw.get(opcion)
        if not data:
            continue
        pdf.add_page()
        pdf.seccion(f"Modulo: {etiqueta}")
        pdf.cuerpo(str(data.get("resultado", ""))[:6000])

    if diff_texto:
        pdf.add_page()
        pdf.seccion("Cambios detectados desde el escaneo anterior")
        pdf.cuerpo(diff_texto[:6000])

    nombre = f"{target.replace('.', '_').replace(':', '_')}_{datetime.now().strftime('%Y-%m-%d_%H%M')}.pdf"
    ruta = os.path.join(REPORTS_DIR, nombre)
    pdf.output(ruta)
    return ruta
