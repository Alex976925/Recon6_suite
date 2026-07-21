"""
Módulo de analítica para Recon6_Suite.

Convierte las salidas de texto plano que ya producen las funciones de
utils/herramientas.py en estructuras de datos (dicts/listas) listas para
alimentar las tarjetas KPI, las gráficas (Chart.js) y el grafo (vis-network)
del nuevo dashboard, sin modificar la lógica original de escaneo.

También mantiene un almacén simple en disco (JSON) por objetivo (target)
para poder combinar resultados de distintos tipos de escaneo (whois, dns,
nmap, subdominios, correos, tecnologías) sobre un mismo dominio/IP y para
llevar un historial de "risk score" a través del tiempo.
"""

import json
import os
import re
from datetime import datetime

STORE_PATH = "data_store.json"

CATEGORIAS_TECH = {
    "Backend": ["php", "asp.net", "django", "flask", "express", "laravel", "ruby", "python", "java", "node"],
    "Frontend": ["jquery", "vue", "angular", "react", "bootstrap"],
    "CDN": ["cloudflare", "akamai", "fastly", "cloudfront"],
    "Database": ["mysql", "postgres", "mongodb", "mariadb", "mssql"],
    "Infrastructure": ["nginx", "apache", "iis", "litespeed", "gunicorn", "cloudflare"],
}

SEVERIDAD_PUERTOS = {
    21: "high", 23: "high", 3389: "high", 445: "high", 139: "high",
    3306: "medium", 5432: "medium", 1433: "medium", 6379: "medium",
    80: "low", 443: "low", 22: "low", 25: "low",
}


def _cargar_store():
    if not os.path.exists(STORE_PATH):
        return {}
    try:
        with open(STORE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _guardar_store(store):
    with open(STORE_PATH, "w", encoding="utf-8") as f:
        json.dump(store, f, ensure_ascii=False, indent=2)


def registrar_resultado(target, opcion, resultado):
    """Guarda el resultado crudo de un escaneo bajo su target, y agrega
    una entrada al historial de risk score una vez recalculado."""
    store = _cargar_store()
    entry = store.setdefault(target, {"scans": {}, "history": []})

    anterior = entry["scans"].get(opcion)
    entry["scans"][opcion] = {
        "resultado": resultado,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "anterior": {
            "resultado": anterior["resultado"],
            "timestamp": anterior["timestamp"],
        } if anterior else None,
    }
    resumen = construir_resumen(target, entry["scans"])
    entry["history"].append({
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "risk_score": resumen["kpis"]["risk_score"],
    })
    entry["history"] = entry["history"][-20:]
    _guardar_store(store)
    return resumen


def obtener_resumen(target):
    store = _cargar_store()
    entry = store.get(target)
    if not entry:
        return resumen_vacio(target)
    return construir_resumen(target, entry["scans"], entry.get("history", []))


def resumen_vacio(target=""):
    return {
        "target": target,
        "kpis": {"open_ports": 0, "subdomains": 0, "technologies": 0, "emails": 0, "risk_score": 0,
                  "ssl_days_left": None, "header_score": None, "takeover_vulnerable": 0},
        "radar": {"DNS Exposure": 0, "Subdomain Exposure": 0, "Port Exposure": 0,
                   "Technology Fingerprint": 0, "Email Exposure": 0, "Header Security": 0},
        "doughnut": {k: 0 for k in list(CATEGORIAS_TECH.keys()) + ["Other"]},
        "history": [],
        "table": [],
        "graph": {"nodes": [], "edges": []},
    }


def _parse_puertos(texto_nmap):
    puertos = []
    if not texto_nmap:
        return puertos
    for linea in texto_nmap.splitlines():
        m = re.match(r"\s*(\d+)/(tcp|udp)\s+(open|filtered)\s+(\S+)(?:\s+(.*))?", linea)
        if m and m.group(3) == "open":
            puertos.append({
                "port": int(m.group(1)),
                "proto": m.group(2),
                "service": m.group(4),
                "version": (m.group(5) or "").strip(),
            })
    return puertos


def _parse_lineas(texto):
    if not texto:
        return []
    return [l.strip() for l in texto.splitlines() if l.strip() and not l.strip().startswith("Error") and not l.strip().startswith("[!]") and not l.strip().startswith("No se")]


def _clasificar_tech(nombre):
    n = nombre.lower()
    for cat, kws in CATEGORIAS_TECH.items():
        if any(kw in n for kw in kws):
            return cat
    return "Other"


def construir_resumen(target, scans, history=None):
    history = history or []

    nmap_txt = scans.get("nmap", {}).get("resultado", "") or scans.get("nmap_prof", {}).get("resultado", "")
    puertos = _parse_puertos(nmap_txt)

    subdominios = _parse_lineas(scans.get("subdom", {}).get("resultado", ""))
    correos = _parse_lineas(scans.get("correos", {}).get("resultado", ""))
    tech_lineas = _parse_lineas(scans.get("tech", {}).get("resultado", ""))
    dns_txt = scans.get("dns", {}).get("resultado", "") or ""
    whois_txt = scans.get("whois", {}).get("resultado", "") or ""
    ssl_txt = scans.get("ssl", {}).get("resultado", "") or ""
    headers_txt = scans.get("headers", {}).get("resultado", "") or ""
    takeover_txt = scans.get("takeover", {}).get("resultado", "") or ""

    # Distribución de tecnologías por categoría
    doughnut = {k: 0 for k in list(CATEGORIAS_TECH.keys()) + ["Other"]}
    tecnologias = []
    for linea in tech_lineas:
        valor = linea.split(":", 1)[-1].strip() if ":" in linea else linea
        cat = _clasificar_tech(valor)
        doughnut[cat] += 1
        tecnologias.append({"nombre": valor, "categoria": cat})

    # KPIs
    open_ports = len(puertos)
    n_subdominios = len(subdominios)
    n_tech = len(tecnologias)
    n_correos = len(correos)

    from utils.ssl_analysis import extraer_datos_ssl
    from utils.security_headers import extraer_score as extraer_header_score
    ssl_info = extraer_datos_ssl(ssl_txt)
    header_score = extraer_header_score(headers_txt) if headers_txt else None
    takeover_vulnerable = takeover_txt.count("VULNERABLE")

    riesgo = 0
    riesgo += min(open_ports * 8, 40)
    riesgo += min(n_correos * 4, 20)
    riesgo += min(n_subdominios * 2, 20)
    riesgo += 10 if any(p["port"] in (21, 23, 3389, 445, 139) for p in puertos) else 0
    riesgo += 10 if n_tech > 0 else 0
    riesgo += 15 if ssl_info.get("vencido") else 0
    riesgo += 10 if ssl_info.get("debil") else 0
    riesgo += 25 * takeover_vulnerable
    if header_score is not None:
        riesgo += max(0, (100 - header_score) // 5)
    risk_score = min(riesgo, 100)

    # Radar (0-100 por dimensión) — usa datos reales cuando el módulo ya se corrió
    radar = {
        "DNS Exposure": min(len(re.findall(r"^(A|MX|NS|TXT):", dns_txt, re.M)) * 15, 100),
        "Subdomain Exposure": min(n_subdominios * 8, 100),
        "Port Exposure": min(open_ports * 15, 100),
        "Technology Fingerprint": min(n_tech * 20, 100),
        "Email Exposure": min(n_correos * 15, 100),
        "Header Security": (100 - header_score) if header_score is not None else (60 if any(p["port"] == 443 for p in puertos) else 40),
    }

    # Tabla técnica
    tabla = []
    for p in puertos:
        severidad = SEVERIDAD_PUERTOS.get(p["port"], "medium")
        tabla.append({
            "host": target, "ip": target if _es_ip(target) else "",
            "port": p["port"], "service": p["service"], "state": "open",
            "technology": p["version"] or "-", "severity": severidad,
            "last_seen": scans.get("nmap", scans.get("nmap_prof", {})).get("timestamp", ""),
        })

    subdominios_vulnerables = re.findall(r"^(\S+) → CNAME: (\S+) \[(\S+)\] → VULNERABLE", takeover_txt, re.M)
    for sub, cname, proveedor in subdominios_vulnerables:
        tabla.append({
            "host": sub, "ip": "", "port": "-", "service": "subdomain takeover",
            "state": "TAKEOVER", "technology": proveedor, "severity": "high",
            "last_seen": scans.get("takeover", {}).get("timestamp", ""),
        })

    # Grafo de relaciones
    nodes = [{"id": target, "label": target, "group": "domain"}]
    edges = []
    subs_vulnerables_set = {s for s, _, _ in subdominios_vulnerables}
    for sd in subdominios[:40]:
        grupo = "vulnerable" if sd in subs_vulnerables_set else "subdomain"
        nodes.append({"id": sd, "label": sd, "group": grupo})
        edges.append({"from": target, "to": sd})
    for p in puertos:
        nid = f"port:{p['port']}"
        nodes.append({"id": nid, "label": f"{p['port']}/{p['service']}", "group": "port"})
        edges.append({"from": target, "to": nid})
    for t in tecnologias:
        nid = f"tech:{t['nombre']}"
        nodes.append({"id": nid, "label": t["nombre"], "group": "technology"})
        edges.append({"from": target, "to": nid})
    if whois_txt and not whois_txt.startswith("Error"):
        nodes.append({"id": "whois", "label": "WHOIS Record", "group": "info"})
        edges.append({"from": target, "to": "whois"})
    if ssl_txt and not ssl_txt.startswith("Error"):
        etiqueta_ssl = f"SSL ({ssl_info.get('dias_restantes')}d)" if ssl_info.get("dias_restantes") is not None else "SSL Cert"
        nodes.append({"id": "ssl", "label": etiqueta_ssl, "group": "vulnerable" if ssl_info.get("vencido") else "info"})
        edges.append({"from": target, "to": "ssl"})
    if headers_txt and header_score is not None:
        nodes.append({"id": "headers", "label": f"Headers ({header_score}/100)", "group": "info" if header_score >= 60 else "vulnerable"})
        edges.append({"from": target, "to": "headers"})

    return {
        "target": target,
        "kpis": {
            "open_ports": open_ports, "subdomains": n_subdominios,
            "technologies": n_tech, "emails": n_correos, "risk_score": risk_score,
            "ssl_days_left": ssl_info.get("dias_restantes"),
            "header_score": header_score,
            "takeover_vulnerable": takeover_vulnerable,
        },
        "radar": radar,
        "doughnut": doughnut,
        "history": history,
        "table": tabla,
        "graph": {"nodes": nodes, "edges": edges},
    }


def _es_ip(valor):
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", valor))


def calcular_diff(target):
    """Compara, para cada tipo de escaneo ya ejecutado sobre el target, el
    resultado actual contra el inmediatamente anterior, y devuelve qué
    líneas son nuevas y cuáles desaparecieron (subdominios nuevos, puertos
    que se cerraron, correos nuevos, tecnologías que cambiaron, etc.)."""
    store = _cargar_store()
    entry = store.get(target)
    if not entry:
        return {}

    diffs = {}
    for opcion, data in entry.get("scans", {}).items():
        anterior = data.get("anterior")
        if not anterior:
            diffs[opcion] = {"estado": "primer_escaneo", "nuevas": [], "eliminadas": [],
                               "timestamp_actual": data.get("timestamp"), "timestamp_anterior": None}
            continue

        actuales = set(_parse_lineas(data.get("resultado", "")))
        previas = set(_parse_lineas(anterior.get("resultado", "")))
        nuevas = sorted(actuales - previas)
        eliminadas = sorted(previas - actuales)

        diffs[opcion] = {
            "estado": "sin_cambios" if not nuevas and not eliminadas else "cambios_detectados",
            "nuevas": nuevas,
            "eliminadas": eliminadas,
            "timestamp_actual": data.get("timestamp"),
            "timestamp_anterior": anterior.get("timestamp"),
        }
    return diffs


def formatear_diff(diffs, opcion_labels=None):
    opcion_labels = opcion_labels or {}
    if not diffs:
        return "No hay historial suficiente todavía. Ejecuta al menos dos escaneos sobre el mismo target."

    lineas = []
    for opcion, d in diffs.items():
        etiqueta = opcion_labels.get(opcion, opcion)
        if d["estado"] == "primer_escaneo":
            lineas.append(f"● {etiqueta}: primer escaneo registrado, sin punto de comparación aún.")
            continue
        if d["estado"] == "sin_cambios":
            lineas.append(f"● {etiqueta}: sin cambios desde {d['timestamp_anterior']}.")
            continue
        lineas.append(f"● {etiqueta}: cambios desde {d['timestamp_anterior']} → {d['timestamp_actual']}")
        for item in d["nuevas"]:
            lineas.append(f"    + {item}")
        for item in d["eliminadas"]:
            lineas.append(f"    - {item}")
    return "\n".join(lineas)
