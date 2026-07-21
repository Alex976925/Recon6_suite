"""
Gestión de configuración de Recon6_Suite.

Guarda claves de API opcionales (Shodan, VirusTotal, HaveIBeenPwned,
Censys) en un archivo JSON local, fuera del control de versiones.
Todos los módulos que dependen de una API externa consultan este
archivo y, si la clave no está configurada, lo informan claramente
en vez de fallar o simular una respuesta.
"""

import json
import os

CONFIG_PATH = "config.json"

DEFAULTS = {
    "shodan_api_key": "",
    "virustotal_api_key": "",
    "hibp_api_key": "",
    "censys_api_id": "",
    "censys_api_secret": "",
    "nvd_api_key": "",  # opcional: sin ella la API de NVD igual funciona, más lenta
}


def cargar_config():
    if not os.path.exists(CONFIG_PATH):
        return dict(DEFAULTS)
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        merged = dict(DEFAULTS)
        merged.update(data)
        return merged
    except Exception:
        return dict(DEFAULTS)


def guardar_config(nuevo):
    actual = cargar_config()
    actual.update({k: v for k, v in nuevo.items() if k in DEFAULTS})
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(actual, f, indent=2)
    return actual


def tiene_clave(nombre):
    return bool(cargar_config().get(nombre))
