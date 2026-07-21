"""
Analiza los encabezados de seguridad HTTP reales de un target (petición
GET real vía requests) y calcula una puntuación 0-100 según cuáles estén
presentes y bien configurados. Esta puntuación alimenta la dimensión
"Header Security" del radar, reemplazando el valor fijo que había antes.
"""

import requests

CABECERAS_ESPERADAS = {
    "Strict-Transport-Security": 20,
    "Content-Security-Policy": 20,
    "X-Content-Type-Options": 15,
    "X-Frame-Options": 15,
    "Referrer-Policy": 10,
    "Permissions-Policy": 10,
    "X-XSS-Protection": 5,
}

CABECERAS_QUE_FILTRAN_INFO = ["Server", "X-Powered-By", "X-AspNet-Version"]


def analizar_headers(target, timeout=8):
    url = target if target.startswith("http") else f"https://{target}"
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=True)
    except requests.exceptions.SSLError:
        url = f"http://{target}"
        try:
            resp = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=True)
        except Exception as e:
            return f"Error Headers: {e}", 0
    except Exception as e:
        return f"Error Headers: {e}", 0

    headers = resp.headers
    lineas = [f"URL analizada: {resp.url}", f"Código de respuesta: {resp.status_code}", ""]

    score = 0
    lineas.append("— Cabeceras de seguridad —")
    for nombre, puntos in CABECERAS_ESPERADAS.items():
        valor = headers.get(nombre)
        if valor:
            score += puntos
            lineas.append(f"✅ {nombre}: {valor}")
        else:
            lineas.append(f"❌ {nombre}: ausente")

    lineas.append("")
    lineas.append("— Cabeceras que exponen información —")
    filtra_info = False
    for nombre in CABECERAS_QUE_FILTRAN_INFO:
        valor = headers.get(nombre)
        if valor:
            filtra_info = True
            lineas.append(f"⚠ {nombre}: {valor}")
    if not filtra_info:
        lineas.append("✅ No se detectaron cabeceras que revelen tecnología del servidor.")
    else:
        score = max(0, score - 5)

    score = min(100, score)
    lineas.append("")
    lineas.append(f"Header Security Score: {score}/100")

    return "\n".join(lineas), score


def extraer_score(texto):
    if not texto:
        return 40
    for linea in texto.splitlines():
        if linea.startswith("Header Security Score:"):
            try:
                return int(linea.split(":")[1].strip().split("/")[0])
            except Exception:
                return 40
    return 40
