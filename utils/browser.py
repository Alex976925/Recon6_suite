"""
Helper compartido para lanzar Chromium vía Playwright, usado tanto por
utils/screenshots.py como por utils/pdf_visual.py.

Si el navegador que Playwright descarga normalmente (~300MB) no está
instalado, en vez de fallar de inmediato se busca un Chromium/Chrome ya
presente en el sistema (útil en Termux con `pkg install chromium`, o en
Debian/Ubuntu con `apt install chromium`), o se respeta la variable de
entorno RECON6_CHROME_PATH si el usuario quiere apuntar a un binario
específico.
"""

import os
import shutil

RUTAS_COMUNES = [
    "chromium", "chromium-browser", "google-chrome", "google-chrome-stable",
    "/data/data/com.termux/files/usr/bin/chromium",  # Termux (pkg install chromium)
    "/usr/bin/chromium", "/usr/bin/chromium-browser", "/usr/bin/google-chrome",
    "/snap/bin/chromium",
]


def _buscar_binario_sistema():
    override = os.environ.get("RECON6_CHROME_PATH")
    if override and os.path.exists(override):
        return override
    for candidato in RUTAS_COMUNES:
        ruta = shutil.which(candidato) if not candidato.startswith("/") else (candidato if os.path.exists(candidato) else None)
        if ruta:
            return ruta
    return None


def lanzar_chromium(playwright_instance, headless=True):
    """Intenta lanzar con el binario que Playwright gestiona; si no está
    instalado, cae a un Chromium/Chrome del sistema si lo encuentra."""
    try:
        return playwright_instance.chromium.launch(headless=headless)
    except Exception as primer_error:
        binario = _buscar_binario_sistema()
        if not binario:
            raise primer_error
        return playwright_instance.chromium.launch(headless=headless, executable_path=binario)
