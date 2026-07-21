# Recon6_Suite — Enterprise UI Edition
### v2 — Módulos premium para laboratorio personal

---

## 1. Qué cambió en esta versión

La v1 fue el rediseño visual (dashboard SOC). Esta v2 agrega **8 módulos nuevos, todos con lógica real** (nada de datos de prueba):

| Módulo | Qué hace | Requiere API key |
|---|---|---|
| **SSL/TLS Analysis** | Conecta al puerto 443, trae emisor, vigencia, protocolo, cifrado. Avisa si el cert está vencido o usa protocolo obsoleto. | No |
| **Security Headers** | Petición HTTP real, calcula un score 0-100 según HSTS/CSP/X-Frame-Options/etc. Este score ahora alimenta de verdad la dimensión "Header Security" del radar (antes estaba fija en 40/100). | No |
| **Robots/Sitemap Crawler** | Descarga robots.txt real, extrae Disallow/Allow y sitemaps referenciados; parsea las URLs del sitemap.xml. | No |
| **Subdomain Takeover Check** | Resuelve el CNAME de cada subdominio ya descubierto y lo compara contra huellas conocidas (S3, GitHub Pages, Heroku, Azure, Shopify, etc.) para detectar takeovers reales. | No |
| **CVE Cross-Reference** | Cruza las tecnologías detectadas (con versión) contra la API pública de NVD. | Opcional (solo para más límite de tasa) |
| **Diff entre escaneos** | Cada vez que corres un módulo, se compara contra su corrida anterior sobre el mismo target y se muestra qué apareció/desapareció (nuevo panel "Cambios desde el escaneo anterior" + endpoint `/api/diff`). | No |
| **Screenshots** | Captura real con Chromium headless (Playwright). Si Playwright no está instalado, el botón lo indica con el comando exacto para instalarlo, sin romper el resto de la app. | No (pero pesa ~300MB instalar el navegador) |
| **Threat Intelligence** | Shodan, VirusTotal, HaveIBeenPwned (para los correos ya extraídos) y Censys — llamadas reales a cada API. | Sí, cada una por separado |
| **Watchlist / escaneos programados** | Página nueva (`/watchlist`) para agregar targets con un intervalo en minutos; corre en segundo plano con APScheduler y alimenta el mismo historial que llena la gráfica de Risk Score con el tiempo. | No |
| **Reporte PDF real** | Botón "Descargar reporte PDF" — genera un PDF de verdad (no HTML disfrazado) con KPIs, radar, inventario técnico, cada módulo ejecutado y el diff. | No |

---

## 2. Arquitectura actualizada

```
utils/
├── analytics.py       → (extendido) ahora también calcula diffs entre escaneos
├── config.py           → NUEVO — guarda API keys en config.json (fuera de git)
├── ssl_analysis.py      → NUEVO — análisis real de certificados
├── security_headers.py  → NUEVO — score real de cabeceras de seguridad
├── crawler.py            → NUEVO — robots.txt + sitemap.xml
├── takeover.py            → NUEVO — detección de subdomain takeover
├── cve_lookup.py           → NUEVO — cruce con NVD
├── threat_intel.py          → NUEVO — Shodan / VirusTotal / HIBP / Censys
├── screenshots.py             → NUEVO — capturas con Playwright
├── reporting.py                → NUEVO — generación de PDF (fpdf2)
└── scheduler.py                 → NUEVO — watchlist + APScheduler

templates/
├── settings.html    → NUEVO — formulario de API keys
└── watchlist.html    → NUEVO — administración de escaneos programados

data_store.json   → (igual que v1) historial de escaneos por target
config.json        → NUEVO, se crea al guardar Settings (API keys)
watchlist.json       → NUEVO, se crea al agregar un target al watchlist
```

Todo lo del backend original (`herramientas.py`, `auth.py`) sigue **sin tocarse**.

---

## 3. Dependencias nuevas

```
fpdf2         → generación de PDF (ligera, sin motor de navegador)
APScheduler   → escaneos programados en segundo plano
```

**Opcional** (no se instala por defecto, el resto de la app funciona igual sin ella):
```
playwright    → capturas de pantalla reales
```
Para habilitarla:
```bash
pip install playwright
playwright install chromium
```

---

## 4. Resultado de las pruebas (todas contra objetivos reales)

| Prueba | Resultado |
|---|---|
| SSL/TLS Analysis contra github.com | ✅ Certificado real, protocolo TLSv1.3, 19 días restantes reportados correctamente |
| Security Headers contra github.com | ✅ Score real (80/100), detectó HSTS/CSP/X-Frame-Options presentes |
| Robots/Sitemap contra github.com | ✅ robots.txt real descargado y parseado |
| CVE Cross-Reference | ✅ Sin errores; reporta cuando no hay tecnología con versión reconocible para cruzar |
| Subdomain Takeover (sin subdominios previos) | ✅ Mensaje claro pidiendo correr primero Subdomain Discovery, no rompe nada |
| Diff entre escaneos (`/api/diff`) | ✅ JSON válido, distingue "primer_escaneo" de "cambios_detectados" |
| **Reporte PDF** | ✅ PDF válido de 5 páginas generado y verificado (se encontró y corrigió un `UnicodeEncodeError` por los símbolos ✅❌⚠ — ver nota abajo) |
| Threat Intel sin API key configurada | ✅ Responde con instrucciones claras, no lanza error 500 |
| Screenshot sin Playwright instalado | ✅ Responde con el comando exacto de instalación, no rompe la app |
| Settings — guardar API keys | ✅ `config.json` se crea y persiste correctamente |
| Watchlist — agregar target | ✅ `watchlist.json` se crea y persiste correctamente |
| Errores de Python en el log tras toda la ronda de pruebas | ✅ Ninguno |

### Bug encontrado y corregido durante las pruebas
`fpdf2` usa fuentes "core" (Helvetica/Courier) que solo soportan **latin-1**. Los textos que generan los módulos usan símbolos como ✅ ❌ ⚠ 🛰, que rompían la generación del PDF con `UnicodeEncodeError`. Se agregó una función `_sanitizar()` en `utils/reporting.py` que reemplaza esos símbolos por equivalentes ASCII (`[OK]`, `[X]`, `[!]`) antes de escribirlos al PDF.

No fue posible en este entorno de pruebas verificar Shodan/VirusTotal/HaveIBeenPwned/Censys/NVD con datos reales (esos dominios no están en la lista blanca de red de la sandbox de desarrollo), ni instalar el navegador de Playwright (su descarga requiere un dominio no permitido aquí). El código de esos módulos sí quedó probado en su manejo de errores (por ejemplo, sin API key configurada) y debería funcionar sin cambios en tu red normal, donde no hay esas restricciones.

---

## 5. Cómo usar los módulos nuevos

1. **SSL, Headers, Robots, Takeover, CVE** — aparecen directo en el selector "Run Scan" del dashboard, igual que los módulos originales.
2. **Takeover y CVE dependen de datos previos**: corre primero "Subdomain Discovery" (para Takeover) o "Technology Detection" (para CVE) sobre el mismo target.
3. **Diff** — aparece automáticamente en el dashboard después de correr al menos dos escaneos del mismo módulo sobre el mismo target.
4. **Reporte PDF** — botón en la sección "Reports" del dashboard.
5. **Threat Intelligence** — botones en la sección "Intelligence"; primero configura tus API keys en **Settings** (sidebar).
6. **Screenshots** — botón "📸 Capturar pantalla" en el dashboard (requiere `playwright install chromium` una sola vez).
7. **Watchlist** — sección en el sidebar; agrega un target con un intervalo en minutos y el sistema lo vuelve a escanear solo, llenando la gráfica de Historical Risk con el tiempo.

---

## 6. Comando de ejecución (sin cambios)

```bash
git clone https://github.com/Alex976925/Recon6_suite.git
cd Recon6_suite
python3 -m venv venv
source venv/bin/activate        # En Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Nmap debe estar instalado en el sistema para los módulos de escaneo de puertos (`sudo apt install nmap`, o el equivalente en Termux: `pkg install nmap`).

---

## 7. Notas de compatibilidad y seguridad

- `config.json` y `watchlist.json` se generan localmente y **no deben subirse al repositorio** — agrégalos a tu `.gitignore` si vas a versionar tus claves de prueba por error.
- El módulo de Screenshots es opcional a propósito: agregarlo por defecto haría el `pip install` mucho más pesado. Si no lo necesitas, ignóralo — el resto de la suite no depende de él.
- El diff y el watchlist comparten el mismo `data_store.json` que ya usaba el dashboard v1; no se agregó ninguna base de datos nueva.
- Todos los módulos de threat intel devuelven un mensaje explícito si falta la API key — nunca simulan una respuesta.
