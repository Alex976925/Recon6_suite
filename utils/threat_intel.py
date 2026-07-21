"""
Integraciones reales con fuentes de threat intelligence externas. Cada
función hace la llamada HTTP real a la API correspondiente; si no hay
clave configurada en config.json, lo dice explícitamente en vez de
simular una respuesta — nada de datos de prueba/mock.
"""

import requests
from utils.config import cargar_config


def _sin_clave(servicio, campo_config):
    return (f"[!] {servicio} no está configurado. Agrega tu API key en "
            f"Settings (campo '{campo_config}') para habilitar esta consulta. "
            f"Es gratis obtener una clave en el sitio oficial de {servicio}.")


def consultar_shodan(target, timeout=10):
    config = cargar_config()
    key = config.get("shodan_api_key")
    if not key:
        return _sin_clave("Shodan", "shodan_api_key")
    try:
        resp = requests.get(f"https://api.shodan.io/shodan/host/{target}",
                             params={"key": key}, timeout=timeout)
        if resp.status_code == 404:
            return f"Shodan no tiene datos indexados para {target}."
        if resp.status_code != 200:
            return f"Shodan respondió {resp.status_code}: {resp.text[:200]}"
        data = resp.json()
        lineas = [
            f"IP: {data.get('ip_str')}",
            f"Organización: {data.get('org', 'N/A')}",
            f"Sistema operativo: {data.get('os', 'N/A')}",
            f"País: {data.get('country_name', 'N/A')}",
            f"Puertos indexados: {', '.join(map(str, data.get('ports', [])))}",
        ]
        for item in data.get("data", [])[:8]:
            lineas.append(f"  - Puerto {item.get('port')}: {item.get('product', '')} {item.get('version', '')}".strip())
        return "\n".join(lineas)
    except Exception as e:
        return f"Error consultando Shodan: {e}"


def consultar_virustotal(target, timeout=10):
    config = cargar_config()
    key = config.get("virustotal_api_key")
    if not key:
        return _sin_clave("VirusTotal", "virustotal_api_key")
    try:
        resp = requests.get(f"https://www.virustotal.com/api/v3/domains/{target}",
                             headers={"x-apikey": key}, timeout=timeout)
        if resp.status_code != 200:
            return f"VirusTotal respondió {resp.status_code}: {resp.text[:200]}"
        data = resp.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        lineas = [
            f"Reputación: {data.get('reputation', 'N/A')}",
            f"Motores maliciosos: {stats.get('malicious', 0)}",
            f"Motores sospechosos: {stats.get('suspicious', 0)}",
            f"Motores limpios: {stats.get('harmless', 0)}",
            f"Categorías: {', '.join(data.get('categories', {}).values()) or 'N/A'}",
        ]
        return "\n".join(lineas)
    except Exception as e:
        return f"Error consultando VirusTotal: {e}"


def consultar_hibp(correo, timeout=10):
    config = cargar_config()
    key = config.get("hibp_api_key")
    if not key:
        return _sin_clave("HaveIBeenPwned", "hibp_api_key")
    try:
        resp = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{correo}",
            headers={"hibp-api-key": key, "User-Agent": "Recon6_Suite"},
            params={"truncateResponse": "false"}, timeout=timeout,
        )
        if resp.status_code == 404:
            return f"{correo}: no aparece en brechas conocidas."
        if resp.status_code != 200:
            return f"HIBP respondió {resp.status_code} para {correo}"
        breaches = resp.json()
        lineas = [f"{correo}: encontrado en {len(breaches)} brecha(s):"]
        for b in breaches:
            lineas.append(f"  - {b.get('Name')} ({b.get('BreachDate')}): {', '.join(b.get('DataClasses', []))}")
        return "\n".join(lineas)
    except Exception as e:
        return f"Error consultando HIBP para {correo}: {e}"


def consultar_hibp_lote(correos, timeout=10, limite=15):
    if not correos:
        return "No hay correos para consultar. Ejecuta primero 'Email Harvesting'."
    if not cargar_config().get("hibp_api_key"):
        return _sin_clave("HaveIBeenPwned", "hibp_api_key")
    resultados = []
    for correo in correos[:limite]:
        resultados.append(consultar_hibp(correo, timeout=timeout))
    return "\n\n".join(resultados)


def consultar_censys(target, timeout=10):
    config = cargar_config()
    api_id, secret = config.get("censys_api_id"), config.get("censys_api_secret")
    if not (api_id and secret):
        return _sin_clave("Censys", "censys_api_id / censys_api_secret")
    try:
        resp = requests.get(
            f"https://search.censys.io/api/v2/hosts/{target}",
            auth=(api_id, secret), timeout=timeout,
        )
        if resp.status_code != 200:
            return f"Censys respondió {resp.status_code}: {resp.text[:200]}"
        data = resp.json().get("result", {})
        lineas = [
            f"IP: {data.get('ip')}",
            f"Ubicación: {data.get('location', {}).get('country', 'N/A')}",
            f"Servicios detectados: {len(data.get('services', []))}",
        ]
        for svc in data.get("services", [])[:10]:
            lineas.append(f"  - Puerto {svc.get('port')}: {svc.get('service_name', 'desconocido')}")
        return "\n".join(lineas)
    except Exception as e:
        return f"Error consultando Censys: {e}"
