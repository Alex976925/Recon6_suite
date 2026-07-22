import json
import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, session, send_file, jsonify, url_for

from utils.auth import guardar_usuario, verificar_usuario
from utils.herramientas import (
    whois_lookup, dns_lookup, nmap_scan, nmap_scan_profundo,
    buscar_subdominios, scraping_correos, detectar_tecnologias,
    ataque_fuerza_bruta, guardar_reporte, registrar_log, validar_target
)
from utils.analytics import (
    registrar_resultado, obtener_resumen, resumen_vacio,
    _cargar_store, _parse_lineas, calcular_diff, formatear_diff,
)
from utils.ssl_analysis import analizar_ssl
from utils.security_headers import analizar_headers
from utils.crawler import analizar_robots_sitemap
from utils.takeover import analizar_takeover
from utils.cve_lookup import buscar_cves
from utils.threat_intel import consultar_shodan, consultar_virustotal, consultar_hibp_lote, consultar_censys
from utils.screenshots import capturar_pantalla, playwright_disponible
from utils.reporting import generar_pdf
from utils.pdf_visual import generar_pdf_visual, playwright_disponible as pw_ok_visual
from utils.config import cargar_config, guardar_config
from utils import scheduler as watch

app = Flask(__name__)
app.secret_key = "clave_ultrasecreta"

OPCION_LABELS = {
    "whois": "WHOIS Lookup", "dns": "DNS Lookup", "nmap": "Nmap Scan",
    "nmap_prof": "Nmap Deep Scan", "subdom": "Subdomain Discovery",
    "correos": "Email Harvesting", "tech": "Technology Detection",
    "fuerza": "Exposed Service Check", "ssl": "SSL/TLS Analysis",
    "headers": "Security Headers", "robots": "Robots/Sitemap Crawler",
    "takeover": "Subdomain Takeover Check", "cve": "CVE Cross-Reference",
}


def _requiere_login():
    return not session.get("usuario")


def _handlers_simples(target):
    return {
        "whois": whois_lookup, "dns": dns_lookup, "nmap": nmap_scan,
        "nmap_prof": nmap_scan_profundo, "subdom": buscar_subdominios,
        "correos": scraping_correos, "tech": detectar_tecnologias,
        "fuerza": ataque_fuerza_bruta,
        "ssl": lambda t: analizar_ssl(t),
        "headers": lambda t: analizar_headers(t)[0],
        "robots": lambda t: analizar_robots_sitemap(t)[0],
    }


def _obtener_ultimo(target, opcion):
    store = _cargar_store()
    entry = store.get(target, {})
    return entry.get("scans", {}).get(opcion, {}).get("resultado", "")


@app.route("/", methods=["GET", "POST"])
def index():
    if _requiere_login():
        return redirect("/login")

    resultado = ""
    target = session.get("last_target", "")
    resumen = obtener_resumen(target) if target else resumen_vacio()

    if request.method == "POST":
        target = request.form["target"]
        opcion = request.form["opcion"]
        usuario = session["usuario"]

        if not validar_target(target):
            resultado = "❌ Dominio o IP inválido"
            resumen = resumen_vacio(target)
        else:
            if opcion == "takeover":
                subdominios = _parse_lineas(_obtener_ultimo(target, "subdom"))
                resultado, _ = analizar_takeover(subdominios)
                registrar_log(usuario, target, opcion)
                resumen = registrar_resultado(target, opcion, resultado)
                session["last_target"] = target

            elif opcion == "cve":
                tech_lineas = _parse_lineas(_obtener_ultimo(target, "tech"))
                resultado = buscar_cves(tech_lineas)
                registrar_log(usuario, target, opcion)
                resumen = registrar_resultado(target, opcion, resultado)
                session["last_target"] = target

            elif opcion in _handlers_simples(target):
                resultado = _handlers_simples(target)[opcion](target)
                registrar_log(usuario, target, opcion)
                resumen = registrar_resultado(target, opcion, resultado)
                session["last_target"] = target

            elif opcion == "guardar":
                contenido = request.form["contenido"]
                archivo = guardar_reporte(target, contenido)
                return send_file(archivo, as_attachment=True)

    diff_texto = ""
    if target:
        diff_texto = formatear_diff(calcular_diff(target), OPCION_LABELS)

    return render_template(
        "index.html", resultado=resultado, target=target,
        resumen=resumen, resumen_json=json.dumps(resumen),
        opcion_labels=OPCION_LABELS, diff_texto=diff_texto,
        last_scan_time=datetime.now().strftime("%H:%M:%S"),
    )


@app.route("/api/summary")
def api_summary():
    if _requiere_login():
        return jsonify({"error": "no autenticado"}), 401
    target = request.args.get("target") or session.get("last_target", "")
    if not target:
        return jsonify(resumen_vacio())
    return jsonify(obtener_resumen(target))


@app.route("/api/diff")
def api_diff():
    if _requiere_login():
        return jsonify({"error": "no autenticado"}), 401
    target = request.args.get("target") or session.get("last_target", "")
    if not target:
        return jsonify({})
    return jsonify(calcular_diff(target))


@app.route("/reports/pdf")
def reporte_pdf():
    if _requiere_login():
        return redirect("/login")
    target = request.args.get("target") or session.get("last_target", "")
    if not target:
        return redirect("/")
    store = _cargar_store()
    scans_raw = store.get(target, {}).get("scans", {})
    resumen = obtener_resumen(target)
    diff_texto = formatear_diff(calcular_diff(target), OPCION_LABELS)
    ruta = generar_pdf(target, resumen, scans_raw, diff_texto)
    return send_file(ruta, as_attachment=True)


@app.route("/reports/pdf-visual")
def reporte_pdf_visual():
    if _requiere_login():
        return redirect("/login")
    target = request.args.get("target") or session.get("last_target", "")
    if not target:
        return redirect("/")

    resumen = obtener_resumen(target)
    diff_texto = formatear_diff(calcular_diff(target), OPCION_LABELS)

    with open("static/css/style.css", "r", encoding="utf-8") as f:
        css = f.read()
    with open("static/js/dashboard.js", "r", encoding="utf-8") as f:
        dashboard_js = f.read()

    html_renderizado = render_template(
        "report_print.html", target=target, resumen=resumen,
        resumen_json=json.dumps(resumen), diff_texto=diff_texto,
        generado=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        css=css, dashboard_js=dashboard_js,
    )

    ruta, mensaje = generar_pdf_visual(target, html_renderizado)
    if ruta:
        return send_file(ruta, as_attachment=True)

    return (
        f"<body style='background:#0B0F14;color:#F9FAFB;font-family:sans-serif;padding:40px;'>"
        f"<h2 style='color:#FACC15;'>No se pudo generar el reporte visual</h2>"
        f"<pre style='white-space:pre-wrap;'>{mensaje}</pre>"
        f"<a href='/' style='color:#FACC15;'>&larr; Volver al dashboard</a>"
        f"</body>", 200
    )


@app.route("/screenshot", methods=["POST"])
def screenshot():
    if _requiere_login():
        return jsonify({"error": "no autenticado"}), 401
    target = request.form.get("target") or session.get("last_target", "")
    if not target:
        return jsonify({"ok": False, "mensaje": "Sin target activo."})
    ruta, mensaje = capturar_pantalla(target)
    if ruta:
        rel = "/" + ruta.replace("\\", "/")
        return jsonify({"ok": True, "url": rel, "mensaje": mensaje})
    return jsonify({"ok": False, "mensaje": mensaje})


@app.route("/intel/<servicio>")
def intel(servicio):
    if _requiere_login():
        return jsonify({"error": "no autenticado"}), 401
    target = request.args.get("target") or session.get("last_target", "")
    if not target:
        return jsonify({"resultado": "Sin target activo."})
    if servicio == "shodan":
        resultado = consultar_shodan(target)
    elif servicio == "virustotal":
        resultado = consultar_virustotal(target)
    elif servicio == "censys":
        resultado = consultar_censys(target)
    elif servicio == "hibp":
        correos = _parse_lineas(_obtener_ultimo(target, "correos"))
        resultado = consultar_hibp_lote(correos)
    else:
        resultado = "Servicio no reconocido."
    return jsonify({"resultado": resultado})


@app.route("/settings", methods=["GET", "POST"])
def settings():
    if _requiere_login():
        return redirect("/login")
    guardado = False
    if request.method == "POST":
        guardar_config({
            "shodan_api_key": request.form.get("shodan_api_key", "").strip(),
            "virustotal_api_key": request.form.get("virustotal_api_key", "").strip(),
            "hibp_api_key": request.form.get("hibp_api_key", "").strip(),
            "censys_api_id": request.form.get("censys_api_id", "").strip(),
            "censys_api_secret": request.form.get("censys_api_secret", "").strip(),
            "nvd_api_key": request.form.get("nvd_api_key", "").strip(),
        })
        guardado = True
    config = cargar_config()
    return render_template("settings.html", config=config, guardado=guardado,
                            playwright_ok=playwright_disponible())


@app.route("/watchlist", methods=["GET", "POST"])
def watchlist():
    if _requiere_login():
        return redirect("/login")
    if request.method == "POST":
        target = request.form.get("target", "").strip()
        intervalo = request.form.get("intervalo", "60")
        opciones = request.form.getlist("opciones") or watch.OPCIONES_POR_DEFECTO
        if target and validar_target(target):
            watch.agregar_target(target, intervalo_minutos=intervalo, opciones=opciones)
    items = watch.listar_watchlist()
    return render_template("watchlist.html", items=items,
                            scheduler_activo=watch.scheduler_activo(),
                            opciones_disponibles=OPCION_LABELS)


@app.route("/watchlist/quitar/<path:target>")
def watchlist_quitar(target):
    if _requiere_login():
        return redirect("/login")
    watch.quitar_target(target)
    return redirect("/watchlist")


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        usuario = request.form["usuario"]
        clave = request.form["clave"]
        if verificar_usuario(usuario, clave):
            session["usuario"] = usuario
            return redirect("/")
        else:
            error = "Credenciales incorrectas."
    return render_template("login.html", error=error)


@app.route("/registro", methods=["GET", "POST"])
def registro():
    mensaje = ""
    if request.method == "POST":
        usuario = request.form["usuario"]
        clave = request.form["clave"]
        guardar_usuario(usuario, clave)
        mensaje = "Usuario registrado con éxito."
    return render_template("registro.html", mensaje=mensaje)


@app.route("/logout")
def logout():
    session.pop("usuario", None)
    return redirect("/login")


watch.iniciar_scheduler()

if __name__ == "__main__":
    app.run(debug=True)
