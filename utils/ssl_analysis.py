"""
Análisis SSL/TLS real: se conecta al puerto 443 del target, obtiene el
certificado en vivo (sin verificación, para poder inspeccionar incluso
certificados autofirmados/vencidos) y reporta emisor, validez, SANs,
protocolo negociado y cifrado usado.
"""

import socket
import ssl
from datetime import datetime


def _parse_name(name_tuple):
    if not name_tuple:
        return ""
    partes = []
    for rdn in name_tuple:
        for key, value in rdn:
            partes.append(f"{key}={value}")
    return ", ".join(partes)


def analizar_ssl(target, puerto=443, timeout=8):
    if ":" in target:
        target = target.split(":")[0]

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((target, puerto), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert(binary_form=False) or {}
                cert_bin = ssock.getpeercert(binary_form=True)
                protocolo = ssock.version()
                cifrado = ssock.cipher()

        # Con verify_mode = CERT_NONE, getpeercert(binary_form=False) puede
        # venir vacío en algunas versiones de OpenSSL; si pasa, reintenta
        # pidiendo el certificado a pyOpenSSL-less usando el binario crudo.
        if not cert and cert_bin:
            import base64
            der = cert_bin
            pem = ssl.DER_cert_to_PEM_cert(der)
            # Segunda conexión con verificación para poblar el dict, si el
            # certificado es válido; si no, se reporta con lo disponible.
            try:
                ctx2 = ssl.create_default_context()
                with socket.create_connection((target, puerto), timeout=timeout) as sock2:
                    with ctx2.wrap_socket(sock2, server_hostname=target) as ssock2:
                        cert = ssock2.getpeercert(binary_form=False) or {}
            except Exception:
                pass

        emisor = _parse_name(cert.get("issuer"))
        sujeto = _parse_name(cert.get("subject"))
        sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
        not_before = cert.get("notBefore", "")
        not_after = cert.get("notAfter", "")

        dias_restantes = None
        vencido = False
        if not_after:
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                dias_restantes = (exp - datetime.utcnow()).days
                vencido = dias_restantes < 0
            except Exception:
                pass

        lineas = []
        lineas.append(f"Host: {target}:{puerto}")
        lineas.append(f"Protocolo TLS: {protocolo}")
        if cifrado:
            lineas.append(f"Cifrado: {cifrado[0]} ({cifrado[1]}, {cifrado[2]} bits)")
        lineas.append(f"Emisor: {emisor or 'desconocido'}")
        lineas.append(f"Sujeto: {sujeto or 'desconocido'}")
        lineas.append(f"Válido desde: {not_before}")
        lineas.append(f"Válido hasta: {not_after}")
        if dias_restantes is not None:
            estado = "❌ VENCIDO" if vencido else ("⚠ Vence pronto" if dias_restantes < 30 else "✅ Vigente")
            lineas.append(f"Días restantes: {dias_restantes} ({estado})")
        if sans:
            lineas.append(f"SANs ({len(sans)}): " + ", ".join(sans))

        protocolos_debiles = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}
        if protocolo in protocolos_debiles:
            lineas.append(f"⚠ Advertencia: protocolo {protocolo} es obsoleto/inseguro.")

        return "\n".join(lineas)

    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return f"Error SSL: no se pudo conectar a {target}:{puerto} — {e}"
    except Exception as e:
        return f"Error SSL: {e}"


def extraer_datos_ssl(texto):
    """Extrae campos clave del texto de analizar_ssl() para alimentar
    KPIs/tabla del dashboard."""
    datos = {"protocolo": None, "dias_restantes": None, "vencido": False, "sans": [], "debil": False}
    if not texto or texto.startswith("Error"):
        return datos
    for linea in texto.splitlines():
        if linea.startswith("Protocolo TLS:"):
            datos["protocolo"] = linea.split(":", 1)[1].strip()
        elif linea.startswith("Días restantes:"):
            try:
                datos["dias_restantes"] = int(linea.split(":", 1)[1].strip().split(" ")[0])
            except Exception:
                pass
            datos["vencido"] = "VENCIDO" in linea
        elif linea.startswith("SANs"):
            datos["sans"] = [s.strip() for s in linea.split(":", 1)[1].split(",") if s.strip()]
        elif "obsoleto/inseguro" in linea:
            datos["debil"] = True
    return datos
