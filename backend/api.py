import socket
import threading
import time

class Api:
    def __init__(self):
        self._window = None
        self._scanning = False
        self._lang = "es" # default language

    def set_language(self, lang):
        """Llamado desde JS cuando el usuario cambia el idioma."""
        self._lang = lang if lang in ["es", "en"] else "es"
        return {"status": "success", "lang": self._lang}

    def set_window(self, window):
        self._window = window

    def check_connection(self):
        return {"status": "success", "message": "NetShield Bridge Conectado"}

    def start_port_scan(self, target, network_type="domestica"):
        """Inicia el escaneo en un hilo separado."""
        if self._scanning:
            return {"status": "error", "message": "Ya hay un escaneo en curso."}
        
        self._scanning = True
        # Iniciamos el hilo técnico
        thread = threading.Thread(target=self._run_scanner, args=(target, network_type))
        thread.daemon = True
        thread.start()
        return {"status": "success", "message": f"Escaneo iniciado en {target} (Red: {network_type})"}

    def _run_scanner(self, target, network_type):
        """Lógica interna del escáner."""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 8080]
        
        self._log_to_web(f"[SYSTEM] Analizando puertos comunes en {target} ({network_type})...")
        open_ports = []
        
        try:
            try:
                ip = socket.gethostbyname(target)
                if ip != target:
                    msg = f"[SYSTEM] Objetivo resuelto a IP: {ip}" if self._lang == "es" else f"[SYSTEM] Target resolved to IP: {ip}"
                    self._log_to_web(msg)
            except socket.gaierror:
                msg = f"[ERROR] No se pudo resolver el hostname: {target}" if self._lang == "es" else f"[ERROR] Could not resolve hostname: {target}"
                self._log_to_web(msg, color="#ef4444")
                self._scanning = False
                return

            for port in common_ports:
                if not self._scanning: break # Permitir detenerlo
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.0) # Escaneo rápido
                result = sock.connect_ex((ip, port))
                
                if result == 0:
                    msg = f"[FOUND] Puerto {port}: ABIERTO" if self._lang == "es" else f"[FOUND] Port {port}: OPEN"
                    self._log_to_web(msg, color="#10b981")
                    open_ports.append(port)
                
                sock.close()
                time.sleep(0.01) # Pequeño respiro para el hilo
                
            msg = "[SYSTEM] Escaneo finalizado. Analizando vulnerabilidades..." if self._lang == "es" else "[SYSTEM] Scan finished. Analyzing vulnerabilities..."
            self._log_to_web(msg)
            self._provide_recommendations(open_ports, network_type)

        except Exception as e:
            self._log_to_web(f"[ERROR] {str(e)}", color="#ef4444")
        finally:
            self._scanning = False

    def _provide_recommendations(self, open_ports, network_type):
        safe_count = 0
        warning_count = 0
        critical_count = 0
        
        if not open_ports:
            self._log_to_web("[INFO] No se encontraron puertos abiertos. Tu sistema parece seguro frente a un escaneo rápido.", color="#38bdf8")
            self._window.evaluate_js("updateReconChart(1, 0, 0);")
            return

        self._log_to_web("<br>--- REPORTE DE SEGURIDAD ---", color="#f8fafc")
        
        for port in open_ports:
            # FTP
            if port == 21:
                self._log_to_web("[ALERTA] Puerto 21 (FTP) abierto. Protocolo no cifrado. Usa SFTP o FTPS en su lugar.", color="#f59e0b")
                warning_count += 1
            # SSH
            elif port == 22:
                if network_type == "publica":
                    self._log_to_web("[PELIGRO] Puerto 22 (SSH) expuesto en red pública. Altamente riesgoso. Deshabilita o cambia de puerto.", color="#ef4444")
                    critical_count += 1
                else:
                    self._log_to_web("[INFO] Puerto 22 (SSH) abierto. Asegúrate de usar claves públicas sólidas y deshabilitar acceso root por contraseña.", color="#10b981")
                    safe_count += 1
            # Telnet
            elif port == 23:
                self._log_to_web("[CRÍTICO] Puerto 23 (Telnet) abierto. Protocolo obsoleto, TODO el tráfico es en texto plano. ¡CIÉRRALO INMEDIATAMENTE!", color="#ef4444")
                critical_count += 1
            # HTTP/HTTPS
            elif port == 80:
                self._log_to_web("[INFO] Puerto 80 (HTTP) abierto. Considera forzar redirección a HTTPS (Puerto 443).", color="#10b981")
                safe_count += 1
            elif port == 8080:
                if network_type == "publica":
                    self._log_to_web("[ALERTA] Puerto 8080 abierto. Asegura que el servicio web alternativo requiera autenticación.", color="#f59e0b")
                    warning_count += 1
                else:
                    safe_count += 1
            # SMB / Windows File Sharing
            elif port in [135, 139, 445]:
                if network_type == "publica":
                    self._log_to_web(f"[CRÍTICO] Puerto {port} (SMB/RPC) expuesto en red pública. ¡Riesgo altísimo de Ransomware! CIÉRRALO.", color="#ef4444")
                    critical_count += 1
                else:
                    self._log_to_web(f"[ALERTA] Puerto {port} (SMB/RPC) abierto. Deshabilita compartir archivos si no alojas recursos en tu red local.", color="#f59e0b")
                    warning_count += 1
            # Bases de Datos
            elif port == 3306:
                if network_type != "empresarial":
                    self._log_to_web("[PELIGRO] Puerto 3306 (MySQL) abierto. Nunca expongas la base de datos a internet. Usa VPN local o SSH tunneling.", color="#ef4444")
                    critical_count += 1
                else:
                    safe_count += 1
            # RDP
            elif port == 3389:
                if network_type == "publica":
                    self._log_to_web("[CRÍTICO] Puerto 3389 (RDP) abierto. ¡RIESGO EXTREMO! Los ataques de fuerza bruta son constantes. Usa VPN.", color="#ef4444")
                    critical_count += 1
                else:
                    self._log_to_web("[ALERTA] Puerto 3389 (RDP) abierto. Implementa Autenticación a Nivel de Red (NLA) y cambia a un puerto no estándar.", color="#f59e0b")
                    warning_count += 1
            else:
                safe_count += 1
                
        # Send stats to frontend to draw the chart
        should_alert = str(critical_count > 0 and network_type in ["publica", "empresarial"]).lower()
        self._window.evaluate_js(f"updateReconChart({safe_count}, {warning_count}, {critical_count}, {should_alert});")

    def start_web_audit(self, target, ownership="propio", use_proxy=False):
        """Inicia la auditoría web en un hilo separado."""
        if self._scanning:
            return {"status": "error", "message": "Hay una tarea en curso."}
        
        self._scanning = True
        thread = threading.Thread(target=self._run_web_audit, args=(target, ownership, use_proxy))
        thread.daemon = True
        thread.start()
        return {"status": "success", "message": f"Auditoría web iniciada en {target}"}

    def _run_web_audit(self, target, ownership, use_proxy):
        """Lógica interna de auditoría web."""
        self._log_to_web(f"[SYSTEM] Iniciando auditoría web en {target}...", dom_id="output-audit")
        
        if ownership == "ajeno":
            self._log_to_web("<br><b>[ADVERTENCIA ÉTICA]</b>", color="#f59e0b", dom_id="output-audit")
            self._log_to_web("Escanear o auditar dominios ajenos sin autorización expresa no es una buena práctica y puede considerarse una actividad hostil o ilegal dependiendo de tu jurisdicción. Por favor, asegúrate de tener permiso para analizar este objetivo.", color="#f8fafc", dom_id="output-audit")
            self._log_to_web("<br>", dom_id="output-audit")
            
        try:
            import urllib.request
            import urllib.error
            from backend.proxy_manager import ProxyManager
            
            # Configuramos el enrutador de proxy rotativo aleatorio
            try:
                if use_proxy:
                    selected_proxy = ProxyManager.setup_random_proxy()
                    msg = f"[SYSTEM] Rotación IP activada. Saltando por proxy: {selected_proxy}" if self._lang == "es" else f"[SYSTEM] IP Rotation Active. Hopping via proxy: {selected_proxy}"
                    self._log_to_web(msg, color="#38bdf8", dom_id="output-audit")
                else:
                    ProxyManager.disable_proxy() # Conexión directa
            except Exception as e:
                self._log_to_web(f"[ERROR] Falló la configuración del Proxy: {str(e)}", color="#ef4444", dom_id="output-audit")
                self._scanning = False
                return

            url = target
            if not url.startswith("http://") and not url.startswith("https://"):
                url = "http://" + url
            base_url = target.replace("http://", "").replace("https://", "").strip("/")

            # 1. Chequeo de HTTPS y Cabeceras
            self._log_to_web("[SYSTEM] Analizando parámetros de seguridad y cabeceras...", dom_id="output-audit")
            req = urllib.request.Request(url, method="GET") # Cambiamos a GET para asegurar redirecciones completas
            try:
                with urllib.request.urlopen(req, timeout=10) as response:
                    final_url = response.geturl()
                    headers = response.info()
                    
                    self._log_to_web(f"[FOUND] Respuesta desde: {final_url}", color="#10b981", dom_id="output-audit")
                    
                    # Chequeo HTTPS Redirect
                    if url.startswith("http://") and final_url.startswith("https://"):
                        self._log_to_web("[OK] Redirección correcta a HTTPS detectada.", color="#10b981", dom_id="output-audit")
                    elif final_url.startswith("http://"):
                        self._log_to_web("[CRÍTICO] El sitio resuelve a HTTP inseguro por defecto.", color="#ef4444", dom_id="output-audit")

                    # Cabeceras Base
                    server = headers.get('Server')
                    x_powered_by = headers.get('X-Powered-By')
                    if server:
                        self._log_to_web(f"[INFO] Server: {server}", color="#38bdf8", dom_id="output-audit")
                        if ownership == "propio":
                            self._log_to_web(f"&nbsp;&nbsp;↳ [RECOMENDACIÓN] Oculta la versión exacta del servidor ('{server}') en configuraciones de apache/nginx.", color="#f59e0b", dom_id="output-audit")
                    if x_powered_by:
                        self._log_to_web(f"[INFO] X-Powered-By: {x_powered_by}", color="#38bdf8", dom_id="output-audit")
                        if ownership == "propio":
                            self._log_to_web(f"&nbsp;&nbsp;↳ [RECOMENDACIÓN] Remueve la cabecera 'X-Powered-By' en el backend para no revelar tu stack ({x_powered_by}).", color="#f59e0b", dom_id="output-audit")

                    # 2. Cabeceras de Seguridad Faltantes
                    self._log_to_web("[SYSTEM] Verificando protección de cabeceras de seguridad...", color="#94a3b8", dom_id="output-audit")
                    security_headers = {
                        "Strict-Transport-Security": "[HSTS] Falta configurar Strict-Transport-Security. Riesgo de ataques MITM y downgrade HTTP.",
                        "X-Frame-Options": "[Clickjacking] Falta X-Frame-Options. Tu sitio puede ser incrustado en iFrames maliciosos.",
                        "X-Content-Type-Options": "[MIME Sniffing] Falta X-Content-Type-Options: nosniff. Riesgo de inyección de recursos cruzados."
                    }
                    
                    for header, warning in security_headers.items():
                        if not headers.get(header):
                            if ownership == "propio":
                                self._log_to_web(f"[ALERTA] {warning}", color="#f59e0b", dom_id="output-audit")
                            else:
                                self._log_to_web(f"[VULN] No tiene implementado: {header}", color="#eab308", dom_id="output-audit")
                        else:
                            self._log_to_web(f"[OK] Cabecera {header} presente.", color="#10b981", dom_id="output-audit")

            except urllib.error.URLError as e:
                self._log_to_web(f"[ERROR] No se pudo establecer conexión inicial: {getattr(e, 'reason', str(e))}", color="#ef4444", dom_id="output-audit")
                self._scanning = False
                return

            # 3. Fuzzing Básico de Archivos Críticos
            self._log_to_web("<br>[SYSTEM] Buscando directorios y archivos comúnmente expuestos...", color="#94a3b8", dom_id="output-audit")
            sensitive_paths = ["/robots.txt", "/.git/config", "/admin/", "/phpinfo.php", "/.env"]
            protocol = "https://" if "https" in url or "https" in final_url else "http://"
            
            for path in sensitive_paths:
                if not self._scanning: break
                fuzz_url = f"{protocol}{base_url}{path}"
                try:
                    req_fuzz = urllib.request.Request(fuzz_url, method="HEAD")
                    with urllib.request.urlopen(req_fuzz, timeout=3) as fuzz_res:
                        if fuzz_res.status in [200, 401, 403]: # 401/403 indica que existe pero está protegido
                            estado_color = "#10b981" if fuzz_res.status == 200 else "#eab308"
                            self._log_to_web(f"[FOUND] Archivo detectado: {path} (HTTP {fuzz_res.status})", color=estado_color, dom_id="output-audit")
                            if fuzz_res.status == 200 and path != "/robots.txt":
                                if ownership == "propio":
                                    self._log_to_web(f"&nbsp;&nbsp;↳ [CRÍTICO] ¡Estás exponiendo {path} públicamente! Bloquea el acceso o bórralo.", color="#ef4444", dom_id="output-audit")
                except urllib.error.URLError:
                    pass # Archivo no encontrado o bloqueado, no reportamos error para no saturar
                time.sleep(0.1)

            self._log_to_web("<br>[SYSTEM] Auditoría avanzada finalizada.", color="#f8fafc", dom_id="output-audit")
        except Exception as e:
            self._log_to_web(f"[ERROR] Excepción inesperada: {str(e)}", color="#ef4444", dom_id="output-audit")
        finally:
            self._scanning = False

    def _log_to_web(self, message, color=None, dom_id="output-recon"):
        """Envía mensajes directamente a la consola del Frontend y a la terminal de Python."""
        
        # 1. Imprimir en Terminal (Removiendo HTML básico como <br>, <b>, etc)
        import re
        clean_msg = re.sub(r'<[^>]+>', '', message)
        clean_msg = clean_msg.replace('&nbsp;', ' ')
        print(clean_msg)
        
        # 2. Ejecutamos JS desde Python para actualizar el DOM Web
        style = f'style="color:{color}"' if color else ""
        safe_message = message.replace("'", "\\'")
        js_code = f"document.getElementById('{dom_id}').innerHTML += '<br><span {style}>{safe_message}</span>';"
        self._window.evaluate_js(js_code)
        # Auto-scroll al final
        self._window.evaluate_js(f"const out = document.getElementById('{dom_id}'); if(out) out.scrollTop = out.scrollHeight;")

    def save_report(self, content, default_filename):
        """Abre un diálogo nativo para guardar el reporte."""
        try:
            import webview
            # Usar save_file dialog
            file_types = ('Archivos de Texto (*.txt)', 'Todos los archivos (*.*)')
            result = self._window.create_file_dialog(webview.SAVE_DIALOG, directory='', save_filename=default_filename, file_types=file_types)
            
            if result and len(result) > 0:
                filepath = result[0]
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
                return {"status": "success", "filepath": filepath}
            return {"status": "cancelled", "message": "Operación cancelada por el usuario"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def start_fuzzing(self, target):
        """Inicia el escaneo de directorios en un hilo separado."""
        if self._scanning:
            return {"status": "error", "message": "Hay una tarea en curso."}
        
        self._scanning = True
        thread = threading.Thread(target=self._run_fuzzing, args=(target,))
        thread.daemon = True
        thread.start()
        return {"status": "success", "message": f"Fuzzing iniciado en {target}"}

    def _run_fuzzing(self, target):
        url = target
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url
        if not url.endswith("/"):
            url += "/"
            
        self._log_to_web(f"[SYSTEM] Iniciando motor de Fuzzing en {url}...", dom_id="output-fuzz")
        
        # Diccionario pequeño de prueba (en un entorno real sería un archivo .txt con miles)
        dictionary = [
            "admin", "login", "wp-admin", "wp-login.php", "backup", "db", "db.sql",
            "backup.zip", "test", ".env", ".git/config", "robots.txt", "phpinfo.php",
            "api", "v1", "swagger.json", "sitemap.xml", "config.php", "server-status"
        ]
        
        try:
            import urllib.request
            import urllib.error
            
            found_count = 0
            for path in dictionary:
                if not self._scanning: break
                
                test_url = url + path
                req = urllib.request.Request(test_url, method="HEAD")
                try:
                    with urllib.request.urlopen(req, timeout=3) as response:
                        if response.status in [200, 301, 302, 401, 403]:
                            color = "#10b981" if response.status == 200 else "#f59e0b"
                            self._log_to_web(f"[FOUND] /{path} (HTTP {response.status})", color=color, dom_id="output-fuzz")
                            found_count += 1
                except urllib.error.URLError as e:
                    if hasattr(e, 'code') and e.code in [401, 403]:
                        # Está prohibido, pero la ruta existe
                        self._log_to_web(f"[FOUND] /{path} (HTTP {e.code} Forbidden/Unauthorized)", color="#f59e0b", dom_id="output-fuzz")
                        found_count += 1
                    pass # Si es 404 (Not Found), lo ignoramos silenciosamente
                time.sleep(0.05) # Pequeño delay de cortesía
                
            self._log_to_web(f"<br>[SYSTEM] Fuzzing finalizado. {found_count} rutas encontradas.", color="#38bdf8", dom_id="output-fuzz")
            
        except Exception as e:
            self._log_to_web(f"[ERROR] {str(e)}", color="#ef4444", dom_id="output-fuzz")
        finally:
            self._scanning = False

    def start_ping_sweep(self, _range):
        """Inicia un rastreo de red en un hilo separado."""
        if self._scanning:
            return {"status": "error", "message": "Hay una tarea en curso."}
            
        self._scanning = True
        thread = threading.Thread(target=self._run_ping_sweep, args=(_range,))
        thread.daemon = True
        thread.start()
        return {"status": "success", "message": f"Ping Sweep iniciado en {_range}"}

    def _run_ping_sweep(self, network_range):
        import subprocess
        import platform
        import ipaddress
        
        self._log_to_web(f"[SYSTEM] Iniciando descubrimiento en red {network_range}...", dom_id="output-ping")
        self._log_to_web(f"[INFO] Esto puede tardar varios minutos dependiendo del tamaño de la red.", color="#94a3b8", dom_id="output-ping")
        
        try:
            net = ipaddress.ip_network(network_range, strict=False)
            hosts = list(net.hosts()) # Generar lista de IPs
            
            # Para no congelarnos escaneando 65535 IPs (red /16), limitamos por ahora a /24
            if len(hosts) > 512:
                self._log_to_web(f"[ERROR] Rango muy grande ({len(hosts)} IPs). Limítalo a un /24 o menor por tu seguridad.", color="#ef4444", dom_id="output-ping")
                self._scanning = False
                return
                
            oper_sys = platform.system().lower()
            found = 0
            
            for ip in hosts:
                if not self._scanning: break
                ip_str = str(ip)
                
                # Comando ping dependiendo del OS (Aceleramos timeouts)
                if oper_sys == "windows":
                    # -n 1 (un paquete), -w 200 (timeout de 200ms)
                    cmd = ["ping", "-n", "1", "-w", "200", ip_str]
                else: 
                    # -c 1 (un paquete), -W 1 (timeout 1 seg)
                    cmd = ["ping", "-c", "1", "-W", "1", ip_str]
                    
                # Ejecutar ping silenciado
                try:
                    result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    if result.returncode == 0:
                        self._log_to_web(f"[FOUND] Equipo activo: {ip_str}", color="#10b981", dom_id="output-ping")
                        found += 1
                except Exception:
                    pass
                    
            self._log_to_web(f"<br>[SYSTEM] Rastreo finalizado. {found} equipos encontrados.", color="#38bdf8", dom_id="output-ping")
            
        except ValueError:
             self._log_to_web(f"[ERROR] Formato de red inválido. Usa formato CIDR Ej: 192.168.1.0/24", color="#ef4444", dom_id="output-ping")
        except Exception as e:
            self._log_to_web(f"[ERROR] {str(e)}", color="#ef4444", dom_id="output-ping")
        finally:
            self._scanning = False

    def start_local_audit(self):
        """Inicia auditoria local en hilo separado (Windows)."""
        if self._scanning:
            return {"status": "error", "message": "Hay una tarea en curso."}
            
        self._scanning = True
        thread = threading.Thread(target=self._run_local_audit)
        thread.daemon = True
        thread.start()
        return {"status": "success", "message": "Auditoría Local Iniciada."}
        
    def _run_local_audit(self):
        import subprocess
        import platform
        
        dom = "output-local"
        self._log_to_web("[SYSTEM] Evaluando host local...", dom_id=dom)
        
        if platform.system().lower() != "windows":
            self._log_to_web("[ALERTA] Este módulo de auditoría local está optimizado para Windows.", color="#f59e0b", dom_id=dom)
            self._scanning = False
            return
            
        try:
            # 1. Chequeo de Firewall
            self._log_to_web("<br>[*] Verificando Perfiles de Windows Firewall...", color="#38bdf8", dom_id=dom)
            cmd_fw = 'powershell "Get-NetFirewallProfile | Format-Table Name, Enabled"'
            res_fw = subprocess.run(cmd_fw, capture_output=True, text=True, shell=True)
            if "False" in res_fw.stdout:
                self._log_to_web("[CRÍTICO] ¡Uno o más perfiles del Firewall están APAGADOS!", color="#ef4444", dom_id=dom)
            else:
                self._log_to_web("[OK] Perfiles de Firewall activos.", color="#10b981", dom_id=dom)
                
            # 2. Chequeo de Antivirus / Defender
            self._log_to_web("<br>[*] Verificando Estado de Windows Defender...", color="#38bdf8", dom_id=dom)
            cmd_av = 'powershell "Get-MpComputerStatus | Select-Object -Property RealTimeProtectionEnabled"'
            res_av = subprocess.run(cmd_av, capture_output=True, text=True, shell=True)
            if "False" in res_av.stdout:
                self._log_to_web("[CRÍTICO] ¡Protección en Tiempo Real DESACTIVADA! Equipo muy vulnerable.", color="#ef4444", dom_id=dom)
            else:
                self._log_to_web("[OK] Protección en Tiempo Real Activa.", color="#10b981", dom_id=dom)

            # 3. Permisos de Administrador Activos (UAC)
            self._log_to_web("<br>[*] Verificando Nivel de Privilegios Locales...", color="#38bdf8", dom_id=dom)
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if is_admin:
                self._log_to_web("[ADVERTENCIA] Estás corriendo este entorno o cuenta como Administrador Global. Cuidado con el malware que ejecutes.", color="#f59e0b", dom_id=dom)
            else:
                self._log_to_web("[OK] Corriendo en modo Usuario Estándar (Menor riesgo de inyección profunda).", color="#10b981", dom_id=dom)
                
            self._log_to_web("<br>[SYSTEM] Auditoría Local Finalizada.", color="#f8fafc", dom_id=dom)
            
        except Exception as e:
            self._log_to_web(f"[ERROR] No se pudo completar la auditoría: {str(e)}", color="#ef4444", dom_id=dom)
        finally:
            self._scanning = False