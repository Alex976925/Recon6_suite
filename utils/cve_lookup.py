"""
Cruza las tecnologías detectadas (con versión, cuando la hay) contra la
API pública de NVD (National Vulnerability Database) para traer CVEs
relacionados. No requiere API key, pero si se configura una en
config.json, se usa para tener mayor límite de tasa.
"""

import re
import requests
from utils.config import cargar_config

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _extraer_producto_version(texto_tech):
    """De una línea como 'Servidor: nginx/1.18.0' o 'Generador: WordPress 6.2'
    intenta sacar (producto, version)."""
    m = re.search(r"([A-Za-z][A-Za-z0-9._-]{2,})[\s/]+v?(\d+(?:\.\d+){1,3})", texto_tech)
    if m:
        return m.group(1), m.group(2)
    return None, None


def buscar_cves(tecnologias, timeout=10, max_items=6):
    """tecnologias: lista de strings crudos (líneas de detectar_tecnologias)."""
    config = cargar_config()
    headers = {}
    if config.get("nvd_api_key"):
        headers["apiKey"] = config["nvd_api_key"]

    lineas = []
    total_cves = 0
    productos_vistos = set()

    for linea in tecnologias:
        producto, version = _extraer_producto_version(linea)
        if not producto:
            continue
        clave = f"{producto.lower()}:{version}"
        if clave in productos_vistos:
            continue
        productos_vistos.add(clave)

        query = f"{producto} {version}"
        try:
            resp = requests.get(
                NVD_URL,
                params={"keywordSearch": query, "resultsPerPage": max_items},
                headers=headers, timeout=timeout,
            )
        except Exception as e:
            lineas.append(f"{producto} {version}: Error consultando NVD — {e}")
            continue

        if resp.status_code == 403:
            lineas.append(f"{producto} {version}: NVD limitó la consulta (rate limit). "
                           f"Configura una API key gratuita en Settings para más margen.")
            continue
        if resp.status_code != 200:
            lineas.append(f"{producto} {version}: NVD respondió {resp.status_code}")
            continue

        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            lineas.append(f"{producto} {version}: sin CVEs encontrados con esa búsqueda.")
            continue

        lineas.append(f"\n{producto} {version} — {len(vulns)} resultado(s):")
        for v in vulns:
            cve = v.get("cve", {})
            cve_id = cve.get("id", "?")
            metrics = cve.get("metrics", {})
            score = "N/A"
            for grupo in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if grupo in metrics and metrics[grupo]:
                    score = metrics[grupo][0].get("cvssData", {}).get("baseScore", "N/A")
                    break
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            desc = (desc[:140] + "…") if len(desc) > 140 else desc
            lineas.append(f"  - {cve_id} (CVSS {score}): {desc}")
            total_cves += 1

    if not lineas:
        return "No se identificaron tecnologías con nombre y versión reconocibles para cruzar contra NVD."

    encabezado = f"Total de CVEs encontrados: {total_cves} en {len(productos_vistos)} tecnología(s) analizada(s)\n"
    return encabezado + "\n".join(lineas)
