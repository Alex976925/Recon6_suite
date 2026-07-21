"""
Detección real de subdomain takeover: para cada subdominio, resuelve su
CNAME; si apunta a un proveedor conocido (S3, GitHub Pages, Heroku,
Azure, etc.) y el contenido de la página coincide con la huella de
"no reclamado" de ese proveedor, se marca como vulnerable.

Referencia de huellas: proyecto público "can-i-take-over-xyz" (patrones
usados también por herramientas como Subjack/Nuclei).
"""

import requests
from utils.analytics import _es_ip
from utils.herramientas import _obtener_resolver
import dns.resolver

FINGERPRINTS = {
    "s3.amazonaws.com": "NoSuchBucket",
    "github.io": "There isn't a GitHub Pages site here",
    "herokuapp.com": "No such app",
    "herokudns.com": "No such app",
    "azurewebsites.net": "404 Web Site not found",
    "cloudapp.net": "404 Web Site not found",
    "wordpress.com": "Do you want to register",
    "shopify.com": "Sorry, this shop is currently unavailable",
    "fastly.net": "Fastly error: unknown domain",
    "readme.io": "Project doesnt exist",
    "surge.sh": "project not found",
    "bitbucket.io": "Repository not found",
    "unbouncepages.com": "The requested URL was not found on this server",
    "pantheonsite.io": "The gods are wise",
    "helpscoutdocs.com": "No settings were found for this company",
    "zendesk.com": "Help Center Closed",
}


def _resolver_cname(subdominio, timeout=6):
    try:
        resolver = _obtener_resolver()
        resolver.lifetime = timeout
        answers = resolver.resolve(subdominio, "CNAME", raise_on_no_answer=False)
        if answers:
            return str(answers[0].target).rstrip(".")
    except Exception:
        pass
    return None


def analizar_takeover(subdominios, timeout=6, limite=60):
    """Recibe una lista de subdominios (por ejemplo, la salida ya parseada
    de buscar_subdominios) y revisa cada uno contra las huellas conocidas."""
    lineas = []
    hallazgos = []

    if not subdominios:
        return "No hay subdominios para analizar. Ejecuta primero 'Subdomain Discovery'.", []

    revisados = 0
    for sub in subdominios:
        if revisados >= limite:
            lineas.append(f"\n[!] Límite de {limite} subdominios revisados por corrida alcanzado.")
            break
        if not sub or _es_ip(sub):
            continue
        revisados += 1

        cname = _resolver_cname(sub, timeout=timeout)
        if not cname:
            continue

        proveedor_match = next((prov for prov in FINGERPRINTS if prov in cname.lower()), None)
        if not proveedor_match:
            continue

        estado = "desconocido"
        try:
            resp = requests.get(f"http://{sub}", timeout=timeout, headers={"User-Agent": "Mozilla/5.0"})
            huella = FINGERPRINTS[proveedor_match]
            if huella.lower() in resp.text.lower():
                estado = "VULNERABLE"
            else:
                estado = "CNAME externo (huella no coincide, probablemente ocupado)"
        except Exception as e:
            estado = f"CNAME externo, no se pudo verificar contenido ({e})"

        linea = f"{sub} → CNAME: {cname} [{proveedor_match}] → {estado}"
        lineas.append(linea)
        hallazgos.append({"subdominio": sub, "cname": cname, "proveedor": proveedor_match, "estado": estado})

    if not lineas:
        return f"Se revisaron {revisados} subdominios; ninguno apunta a un proveedor externo conocido.", []

    resumen = f"Revisados: {revisados} · Con CNAME externo sospechoso: {len(hallazgos)}\n\n" + "\n".join(lineas)
    return resumen, hallazgos
