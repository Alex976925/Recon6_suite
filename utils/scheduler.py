"""
Watchlist + escaneo periódico real usando APScheduler (BackgroundScheduler,
corre dentro del mismo proceso Flask). Cada target en la watchlist se
re-escanea automáticamente con los módulos que el usuario eligió
(por defecto: nmap + subdominios + tech), alimentando el mismo
data_store.json que usa el dashboard — así la línea de "Historical Risk"
se llena sola con el tiempo, sin depender de que el usuario dé clic.
"""

import json
import os
import threading

WATCHLIST_PATH = "watchlist.json"
_scheduler = None
_lock = threading.Lock()

OPCIONES_POR_DEFECTO = ["nmap", "subdom", "tech"]


def _cargar_watchlist():
    if not os.path.exists(WATCHLIST_PATH):
        return []
    try:
        with open(WATCHLIST_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def _guardar_watchlist(items):
    with open(WATCHLIST_PATH, "w", encoding="utf-8") as f:
        json.dump(items, f, indent=2)


def agregar_target(target, intervalo_minutos=60, opciones=None):
    with _lock:
        items = _cargar_watchlist()
        items = [i for i in items if i["target"] != target]
        items.append({
            "target": target,
            "intervalo_minutos": max(5, int(intervalo_minutos)),
            "opciones": opciones or OPCIONES_POR_DEFECTO,
            "activo": True,
        })
        _guardar_watchlist(items)
    _reprogramar()
    return items


def quitar_target(target):
    with _lock:
        items = [i for i in _cargar_watchlist() if i["target"] != target]
        _guardar_watchlist(items)
    _reprogramar()
    return items


def listar_watchlist():
    return _cargar_watchlist()


def _ejecutar_escaneo(target, opciones):
    """Corre en el hilo del scheduler: importa perezosamente para evitar
    ciclos de import con app.py."""
    from utils.herramientas import (
        whois_lookup, dns_lookup, nmap_scan, nmap_scan_profundo,
        buscar_subdominios, scraping_correos, detectar_tecnologias,
    )
    from utils.ssl_analysis import analizar_ssl
    from utils.security_headers import analizar_headers
    from utils.analytics import registrar_resultado

    funciones = {
        "whois": whois_lookup, "dns": dns_lookup, "nmap": nmap_scan,
        "nmap_prof": nmap_scan_profundo, "subdom": buscar_subdominios,
        "correos": scraping_correos, "tech": detectar_tecnologias,
        "ssl": lambda t: analizar_ssl(t),
        "headers": lambda t: analizar_headers(t)[0],
    }
    for opcion in opciones:
        fn = funciones.get(opcion)
        if not fn:
            continue
        try:
            resultado = fn(target)
            registrar_resultado(target, opcion, resultado)
        except Exception as e:
            registrar_resultado(target, opcion, f"Error en escaneo programado: {e}")


def _reprogramar():
    global _scheduler
    if _scheduler is None:
        return
    for job in list(_scheduler.get_jobs()):
        job.remove()
    for item in _cargar_watchlist():
        if not item.get("activo", True):
            continue
        _scheduler.add_job(
            _ejecutar_escaneo, "interval",
            minutes=item["intervalo_minutos"],
            args=[item["target"], item["opciones"]],
            id=f"watch_{item['target']}",
            replace_existing=True,
            next_run_time=None,  # se dispara en el primer intervalo, no de inmediato
        )


def iniciar_scheduler():
    """Debe llamarse una sola vez al arrancar la app Flask. Nunca debe
    tumbar la aplicación: si el scheduler no puede iniciar (por ejemplo,
    en Termux/Android sin el paquete 'tzdata', donde APScheduler no logra
    detectar la zona horaria local), la app sigue funcionando normal y
    solo la Watchlist queda inactiva."""
    global _scheduler
    if _scheduler is not None:
        return _scheduler
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
        import datetime
        # Se fuerza UTC explícito para no depender de tzlocal/zoneinfo
        # detectando la zona horaria del sistema, que en Termux/Android
        # suele fallar por falta del paquete 'tzdata'.
        _scheduler = BackgroundScheduler(daemon=True, timezone=datetime.timezone.utc)
        _scheduler.start()
        _reprogramar()
    except Exception as e:
        print(f"[!] No se pudo iniciar el scheduler de Watchlist: {e}")
        print("    La app sigue funcionando; solo los escaneos programados quedan desactivados.")
        print("    Sugerencia: pip install tzdata")
        _scheduler = None
    return _scheduler


def scheduler_activo():
    return _scheduler is not None
