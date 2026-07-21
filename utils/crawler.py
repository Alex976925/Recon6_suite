"""
Crawler real de robots.txt y sitemap.xml — descubre rutas que el propio
sitio expone (Disallow/Allow, sitemaps referenciados, y las URLs dentro
de esos sitemaps), útil para mapear superficie de ataque sin tocar
endpoints directamente.
"""

import requests
import xml.etree.ElementTree as ET


def _get(url, timeout=8):
    return requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"})


def analizar_robots_sitemap(target, timeout=8):
    base = target if target.startswith("http") else f"https://{target}"
    lineas = []
    rutas = []
    sitemaps = []

    try:
        resp = _get(f"{base}/robots.txt", timeout=timeout)
        if resp.status_code == 200 and resp.text.strip():
            lineas.append("— robots.txt encontrado —")
            for linea in resp.text.splitlines():
                linea = linea.strip()
                if not linea or linea.startswith("#"):
                    continue
                lineas.append(linea)
                if linea.lower().startswith(("disallow:", "allow:")):
                    ruta = linea.split(":", 1)[1].strip()
                    if ruta:
                        rutas.append(ruta)
                elif linea.lower().startswith("sitemap:"):
                    sitemaps.append(linea.split(":", 1)[1].strip())
        else:
            lineas.append(f"robots.txt no disponible (status {resp.status_code}).")
    except Exception as e:
        lineas.append(f"Error obteniendo robots.txt: {e}")

    if not sitemaps:
        sitemaps = [f"{base}/sitemap.xml"]

    lineas.append("")
    lineas.append("— Sitemap(s) —")
    urls_sitemap = []
    for sm_url in sitemaps[:5]:
        try:
            resp = _get(sm_url, timeout=timeout)
            if resp.status_code != 200 or not resp.text.strip():
                lineas.append(f"{sm_url}: no disponible (status {resp.status_code})")
                continue
            lineas.append(f"{sm_url}: OK")
            try:
                root = ET.fromstring(resp.content)
                ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
                locs = [el.text for el in root.findall(".//sm:loc", ns)] or \
                       [el.text for el in root.findall(".//loc")]
                urls_sitemap.extend([l for l in locs if l])
            except ET.ParseError:
                lineas.append("  (no se pudo parsear como XML)")
        except Exception as e:
            lineas.append(f"{sm_url}: Error — {e}")

    if urls_sitemap:
        lineas.append(f"\nURLs encontradas en sitemap ({len(urls_sitemap)}):")
        lineas.extend(urls_sitemap[:200])

    resultado = "\n".join(lineas)
    return resultado, {"rutas_robots": rutas, "urls_sitemap": urls_sitemap}
