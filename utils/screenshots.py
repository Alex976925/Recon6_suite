"""
Captura de pantalla real de un host usando Playwright (Chromium headless).
Playwright es una dependencia pesada (~300MB con el navegador), así que
se importa de forma perezosa: si no está instalado o el navegador no fue
descargado, el módulo lo informa claramente con instrucciones exactas de
instalación, en vez de fallar de forma críptica.
"""

import os
import re
from datetime import datetime

SCREENSHOT_DIR = "static/screenshots"


def _slug(target):
    return re.sub(r"[^a-zA-Z0-9._-]", "_", target)


def playwright_disponible():
    try:
        import playwright  # noqa: F401
        return True
    except ImportError:
        return False


def capturar_pantalla(target, timeout_ms=15000):
    if not playwright_disponible():
        return None, (
            "[!] Playwright no está instalado. Para habilitar capturas de pantalla, corre:\n"
            "    pip install playwright\n"
            "    playwright install chromium\n"
            "(La descarga del navegador requiere conexión a internet; solo se hace una vez).\n"
            "Alternativa más ligera si ya tienes un navegador instalado (ej. en Termux: "
            "pkg install chromium): solo instala 'pip install playwright' — Recon6_Suite "
            "detecta automáticamente un Chromium/Chrome del sistema y lo usa en vez de "
            "descargar uno nuevo."
        )

    from playwright.sync_api import sync_playwright, Error as PlaywrightError
    from utils.browser import lanzar_chromium

    os.makedirs(SCREENSHOT_DIR, exist_ok=True)
    nombre_archivo = f"{_slug(target)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
    ruta = os.path.join(SCREENSHOT_DIR, nombre_archivo)

    url = target if target.startswith("http") else f"https://{target}"

    try:
        with sync_playwright() as p:
            browser = lanzar_chromium(p, headless=True)
            try:
                page = browser.new_page(viewport={"width": 1366, "height": 768})
                try:
                    page.goto(url, timeout=timeout_ms, wait_until="load")
                except PlaywrightError:
                    # Reintenta por http si https falla (certificado, puerto cerrado, etc.)
                    if url.startswith("https"):
                        url_http = url.replace("https://", "http://", 1)
                        page.goto(url_http, timeout=timeout_ms, wait_until="load")
                    else:
                        raise
                page.screenshot(path=ruta, full_page=False)
            finally:
                browser.close()
        return ruta, f"Captura guardada en {ruta}"
    except Exception as e:
        return None, (
            f"[!] No se pudo capturar {target}: {e}\n"
            f"Si es la primera vez que usas esta función, corre: playwright install chromium"
        )
