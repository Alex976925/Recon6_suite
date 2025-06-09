import subprocess, re, requests, ipaddress, os
from bs4 import BeautifulSoup
from datetime import datetime
import whois
import dns.resolver

def es_ip(valor):
    try:
        ipaddress.ip_address(valor)
        return True
    except ValueError:
        return False

def validar_target(target):
    return es_ip(target) or re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", target)

def whois_lookup(target):
    try:
        info = whois.whois(target)
        return str(info)
    except Exception as e:
        return f"Error WHOIS: {e}"

def dns_lookup(target):
    if es_ip(target):
        return "[!] La resolución DNS aplica solo a dominios."
    try:
        resultado = ""
        for qtype in ['A', 'MX', 'NS', 'TXT']:
            answers = dns.resolver.resolve(target, qtype, raise_on_no_answer=False)
            for rdata in answers:
                resultado += f"{qtype}: {rdata.to_text()}\n"
        return resultado
    except Exception as e:
        return f"Error DNS: {e}"

def nmap_scan(target):
    try:
        return subprocess.check_output(
            ['nmap', '-Pn', '-sT', '-sV', '-T4', target],
            stderr=subprocess.STDOUT, universal_newlines=True
        )
    except subprocess.CalledProcessError as e:
        return f"Error Nmap: {e.output}"

def nmap_scan_profundo(target):
    try:
        return subprocess.check_output(
            ['nmap', '-Pn', '-sV', '-A', '-T4', target],
            stderr=subprocess.STDOUT, universal_newlines=True
        )
    except subprocess.CalledProcessError as e:
        return f"Error escaneo profundo: {e.output}"

def buscar_subdominios(target):
    try:
        domain = target.replace("http://", "").replace("https://", "").split('/')[0]
        url = f"https://crt.sh/?q={domain}&output=json"
        resp = requests.get(url, timeout=10)
        subdomains = set()
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                name = entry['name_value']
                for sub in name.split('\n'):
                    subdomains.add(sub.strip())
        return "\n".join(sorted(subdomains))
    except Exception as e:
        return f"Error subdominios: {e}"

def scraping_correos(target):
    try:
        url = f"http://{target}" if not target.startswith("http") else target
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=10)
        correos = re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", response.text)
        unicos = sorted(set(correos))
        return "\n".join(unicos) if unicos else "No se encontraron correos."
    except Exception as e:
        return f"Error scraping: {e}"

def detectar_tecnologias(target):
    try:
        url = f"http://{target}" if not target.startswith("http") else target
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=10)
        tech = []
        server = response.headers.get('Server')
        powered = response.headers.get('X-Powered-By')
        if server: tech.append("Servidor: " + server)
        if powered: tech.append("X-Powered-By: " + powered)
        soup = BeautifulSoup(response.text, 'html.parser')
        metas = soup.find_all('meta')
        for meta in metas:
            if meta.get('name', '').lower() == "generator":
                tech.append("Generador: " + meta.get('content'))
        scripts = soup.find_all("script", src=True)
        for s in scripts:
            if any(x in s['src'].lower() for x in ['jquery', 'vue', 'angular']):
                tech.append("Framework JS detectado: " + s['src'])
        return "\n".join(tech) if tech else "No se detectaron tecnologías."
    except Exception as e:
        return f"Error detectando tecnologías: {e}"

def ataque_fuerza_bruta(target):
    resultado = subprocess.getoutput(f"nmap -p 139,445,3306,3389 --open {target}")
    mensaje = ""
    if "139/tcp open" in resultado:
        mensaje += f"SMB activo. Usa: hydra -L usuarios.txt -P claves.txt smb://{target}\n"
    if "3306/tcp open" in resultado:
        mensaje += f"MySQL activo. Usa: hydra -L usuarios.txt -P claves.txt {target} mysql\n"
    if "3389/tcp open" in resultado:
        mensaje += f"RDP activo. Usa: hydra -L usuarios.txt -P claves.txt rdp://{target}\n"
    return mensaje if mensaje else "No se detectaron servicios vulnerables."

def guardar_reporte(target, contenido):
    if not os.path.exists("reportes"):
        os.makedirs("reportes")
    now = datetime.now().strftime("%Y-%m-%d_%H%M")
    archivo = f"reportes/{target.replace('.', '_')}_{now}.txt"
    with open(archivo, 'w') as f:
        f.write(contenido)
    return archivo

def registrar_log(usuario, target, accion):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("logs.txt", "a") as f:
        f.write(f"[{now}] {usuario} ejecutó {accion} sobre {target}\n")
