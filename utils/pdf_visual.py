"""
Genera un PDF "visual": el mismo dashboard oscuro de Recon6_Suite, con las
gráficas (Chart.js) y el grafo (vis-network) ya renderizados, convertido a
PDF con Chromium headless (Playwright). A diferencia de utils/reporting.py
(texto plano, sin dependencias pesadas), este módulo requiere Playwright +
el navegador Chromium instalado — si no está disponible, lo informa con
instrucciones exactas en vez de fallar.
"""

import os
from datetime import datetime

REPORTS_DIR = "reportes"


def playwright_disponible():
    try:
        import playwright  # noqa: F401
        return True
    except ImportError:
        return False


def generar_pdf_visual(target, html_renderizado):
    """html_renderizado: el HTML ya construido por Flask (render_template
    de templates/report_print.html), con el CSS y el JS del dashboard
    ya inyectados inline para que no dependa de ningún servidor local."""
    if not playwright_disponible():
        return None, (
            "[!] Playwright no está instalado — el reporte visual (con gráficas) "
            "necesita un navegador headless para renderizarlas. Corre:\n"
            "    pip install playwright\n"
            "    playwright install chromium\n"
            "Alternativa más ligera si ya tienes un navegador instalado (ej. en Termux: "
            "pkg install chromium): con 'pip install playwright' basta — Recon6_Suite "
            "detecta automáticamente un Chromium/Chrome del sistema.\n"
            "Mientras tanto, puedes usar el botón 'Reporte PDF (texto)', que no depende de esto."
        )

    from playwright.sync_api import sync_playwright, Error as PlaywrightError
    from utils.browser import lanzar_chromium

    os.makedirs(REPORTS_DIR, exist_ok=True)
    nombre = f"{target.replace('.', '_').replace(':', '_')}_visual_{datetime.now().strftime('%Y-%m-%d_%H%M')}.pdf"
    ruta = os.path.join(REPORTS_DIR, nombre)

    try:
        with sync_playwright() as p:
            browser = lanzar_chromium(p, headless=True)
            try:
                page = browser.new_page(viewport={"width": 1400, "height": 1000})
                page.set_content(html_renderizado, wait_until="networkidle", timeout=20000)
                # Espera a que Chart.js dibuje sus animaciones y el grafo
                # de vis-network termine de estabilizar la física.
                try:
                    page.wait_for_function(
                        "window.Chart !== undefined && document.querySelectorAll('canvas').length > 0",
                        timeout=8000,
                    )
                except PlaywrightError:
                    pass
                page.wait_for_timeout(2200)
                page.pdf(
                    path=ruta,
                    format="A4",
                    landscape=True,
                    print_background=True,
                    margin={"top": "8mm", "bottom": "8mm", "left": "8mm", "right": "8mm"},
                )
            finally:
                browser.close()
        return ruta, "Reporte visual generado correctamente."
    except Exception as e:
        return None, f"[!] No se pudo generar el reporte visual: {e}"
