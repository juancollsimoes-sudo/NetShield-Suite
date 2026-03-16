<h1 align="center">
  <br>
  <img src="https://img.icons8.com/nolan/256/shield.png" alt="NetShield Suite" width="120">
  <br>
  NetShield Suite v1.0
  <br>
</h1>

<h4 align="center">Una herramienta de auditoría de ciberseguridad avanzada y modular, diseñada para el análisis defensivo y ofensivo (Red Team/Blue Team), con una interfaz de usuario híbrida moderna (Python + Interfaz Web).</h4>

<p align="center">
  <a href="#características-principales">Características Principales</a> •
  <a href="#arquitectura-del-proyecto">Arquitectura</a> •
  <a href="#requisitos-del-sistema">Requisitos</a> •
  <a href="#instalación-y-ejecución">Instalación</a> •
  <a href="#uso">Uso</a> •
  <a href="#notas-legales">Notas Legales</a>
</p>

## Características Principales

NetShield Suite no es solo un escáner, es un *framework* compacto de ciberseguridad con capacidades profesionales integradas en una sola aplicación ejecutable (.exe).

*   **Escáner de Puertos Inteligente**: Identifica puertos críticos abiertos, clasifica su nivel de riesgo y genera un gráfico interactivo (Chart.js) en tiempo real con recomendaciones defensivas específicas dependiendo del tipo de red (Doméstica, Empresarial, Pública).
*   **Auditoría Web Avanzada**: Extrae y evalúa las cabeceras de seguridad del servidor objetivo (HSTS, Clickjacking, MIME Sniffing), revisa la redirección SSL/TLS, y alerta sobre configuraciones backend expuestas.
*   **IP Masking (Proxy Automático Aleatorio)**: En ruta tu tráfico a través de una red predefinida de servidores proxy de forma aleatoria, ocultando la dirección IP real de la máquina atacante/auditora durante el reconocimiento web.
*   **Fuzzing de Directorios Ocultos**: Cuenta con un motor de descubrimiento ligero (Fuzzer) integrado que busca rutas críticas expuestas como `/.git/config`, `/.env`, `/admin/` y reporta vulnerabilidades basándose en respuestas HTTP bloqueadas (401/403).
*   **Ping Sweep de Redes Locales**: Capacidades de descubrimiento lateral automatizado que barre bloques de IPs enteras (hasta rangos /24 CIDR) utilizando pulsos rápidos ICMP, para enumerar dispositivos locales sin ruido.
*   **Auditoria Local (Host Health)**: Evalúa la salud defensiva de la propia terminal Windows desde donde se ejecuta la herramienta (Estado de Windows Defender, Perfiles de Firewall por PowerShell, Verificación UAC).
*   **Reportes Técnicos Nativos**: Cada módulo de inspección permite exportar los registros de terminal limpios y formateados a texto plano mediante el gestor nativo del Sistema Operativo para entrega al cliente.
*   **Interfaz Híbrida Adaptable**: Construida sobre UI/UX web dinámica conectada al backend, la aplicación es multi-idioma nativa (Inglés/Español) y soporta perfiles de color Oscuros, Claros e Intermedios configurables.

## Arquitectura del Proyecto

El software fue construido usando una arquitectura **Frontend / Backend dividida**, unidos asíncronamente a través de un puente de procesos IPC nativos de OS (`pywebview`).

```text
NetShield-Suite/
├── main.py                  # El puente de arranque, inicia el webview y conecta el DOM.
├── backend/                 # Lógica Pura y Ciberseguridad (Python Core)
│   ├── api.py               # El "Cerebro". Contienen los algoritmos de Threading, Sockets y Peticiones.
│   └── proxy_manager.py     # Controlador de saltos IP, gestión de rotación en protocolos urllib.
└── web/                     # Interfaz de Usuario y Presentación (HTML/JS/CSS)
    ├── index.html           # Estructura principal y navegación.
    ├── style.css            # Estilos modernos y paletas de temas (CSS Variables).
    ├── script.js            # Lógica cliente y puente JavaScript <-> Python.
    └── i18n.js              # Controlador de diccionarios Multi-Idioma.
```

> **Por qué importa**: Cada proceso de ataque/auditoría (como Ping Sweep o Port Scan) es gestionado en hilos paralelos nativos por `api.py` (con `threading`), por lo que la interfaz de usuario nunca se congela mientras se ejecutan análisis exhaustivos que duran minutos.

## Requisitos del Sistema

### Para Ejecutar la Aplicación Final (Usuario Final)
- **Sistema Operativo**: Windows 10 o Windows 11.
- No se requiere Python pre-instalado si se ejecuta desde la compilación `.exe` proporcionada.
- Se recomienda fuertemente conexión a internet estable.

### Para Entornos de Desarrollo (Desarrolladores)
- **Lenguaje**: Python 3.8+ instalado en la máquina (y listado en el PATH del sistema).
- Mínimo conocimiento manejando la consola `cmd` o PowerShell de Windows.

## Instalación y Ejecución

Puedes elegir entre correr el software desde su código fuente virgen, o a través del modo ejecutable (`.exe`) auto-contenido sin dependencias.

### Opción 1: Ejecutar desde Código Fuente (Dev)

1. **Clona el repositorio**:
   ```bash
   git clone https://github.com/juancollsimoes-sudo/NetShield-Suite.git
   cd NetShield-Suite
   ```

2. **Instala las dependencias del puente nativo**:
   El proyecto utiliza `pywebview` nativo para crear la ventana gráfica interactiva de Chromium/Edge.
   ```bash
   pip install pywebview
   ```

3. **Inicia el programa**:
   Abre la suite en modo desarrollo corriendo el script principal.
   ```bash
   python main.py
   ```

### Opción 2: Compilar el Ejecutable (Producción)

Si realizas tus modificaciones y deseas empacarlo para entregar la Suite sola como programa de escritorio (sin que tus clientes necesiten Python):

1. **Instala PyInstaller**:
   ```bash
   pip install pyinstaller
   ```
2. **Ejecuta el Comando de Ensamblaje**:
   Esto unirá la carpeta `web` como un recurso indexado dentro del script `main.py`.
   ```bash
   python -m PyInstaller --noconsole --onefile --add-data "web;web" main.py -n NetShieldSuite
   ```
   *Encontrarás tu aplicación terminada y autónoma en la carpeta `dist/NetShieldSuite.exe`.*

---

## Uso

NetShield es tan sencillo como encender y auditar. Al iniciar, el usuario debe leer y aceptar los Términos de Uso Ético Internacionales y de la CMAA.

Dentro de las pestañas encontrarás:
1.  **Reconocimiento:** Introduce una IP (ej: `199.170.1.1` o `177.5.9.1`) o un dominio de red. Selecciona el perfil del nivel de alerta y da a Iniciar. Si la red es Pública y detecta puertos peligrosos, lanzará una alerta roja estroboscópica.
2.  **Auditoria Web:** Pega cualquier URL con su esquema Http/Https, activa el toggle Switch the *Rotación de Proxy IP*, para enmascarar tu propio host hacia el objetivo, e inspeciona el backend.
3.  **Local Health:** Evalúa con un solo click los componentes core del SO Windows donde te encuentras sentado trabajando, verificando que tu equipo esté apto.

## Notas Legales y de Advertencia ⚠️

*   **Términos de Responsabilidad**: Esta herramienta y todos los scripts en `backend/` están diseñados estrictamente y sin excepciones para motivos educativos y pruebas de penetración *Blue Team/Red Team* autorizadas.
*   **Cumplimiento CMAA**: Apuntar módulos de análisis de vulnerabilidades integrados (como *Directory Fuzzing* o análisis de Puertos Abiertos Inseguros) hacia dominios u host de terceras partes que no son explícitamente tú propiedad personal - O hacia objetivos e intranets para las cuales No existe Autorización Legal Escrita expedida -, es una ofensa federal de acuerdo al US Computer Fraud and Abuse Act y leyes equivalentes locales.
*   **Autoría**: El(los) autor(es) de "NetShield Suite" derivan toda la culpabilidad civil y legal de los daños provocados por una utilización fraudulenta u ofensiva del presente software. Utilice bajo su rigurosa ética y al amparo de las leyes del estado que habita.
