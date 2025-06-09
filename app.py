from flask import Flask, render_template, request, redirect, session, send_file
from utils.auth import guardar_usuario, verificar_usuario
from utils.herramientas import (
    whois_lookup, dns_lookup, nmap_scan, nmap_scan_profundo,
    buscar_subdominios, scraping_correos, detectar_tecnologias,
    ataque_fuerza_bruta, guardar_reporte, registrar_log, validar_target
)

app = Flask(__name__)
app.secret_key = "clave_ultrasecreta"

@app.route("/", methods=["GET", "POST"])
def index():
    if not session.get("usuario"):
        return redirect("/login")

    resultado = ""
    target = ""

    if request.method == "POST":
        target = request.form["target"]
        opcion = request.form["opcion"]
        usuario = session["usuario"]

        if not validar_target(target):
            resultado = "❌ Dominio o IP inválido"
        else:
            funciones = {
                "whois": whois_lookup,
                "dns": dns_lookup,
                "nmap": nmap_scan,
                "nmap_prof": nmap_scan_profundo,
                "subdom": buscar_subdominios,
                "correos": scraping_correos,
                "tech": detectar_tecnologias,
                "fuerza": ataque_fuerza_bruta
            }

            if opcion in funciones:
                resultado = funciones[opcion](target)
                registrar_log(usuario, target, opcion)

            elif opcion == "guardar":
                contenido = request.form["contenido"]
                archivo = guardar_reporte(target, contenido)
                return send_file(archivo, as_attachment=True)

    return render_template("index.html", resultado=resultado, target=target)

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

if __name__ == "__main__":
    app.run(debug=True)
