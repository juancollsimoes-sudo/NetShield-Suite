import socket
import threading
import time
import re
import subprocess
import platform
import ipaddress
import ctypes
import urllib.request
import urllib.error

class Api:
        def __init__(self):
                self._window = None
                self._scanning = False
                self._lang = "es"

        def set_language(self, lang):
                self._lang = lang if lang in ["es", "en"] else "es"
                return {"status": "success", "lang": self._lang}

        def set_window(self, window):
                self._window = window

        def check_connection(self):
                return {"status": "success", "message": "NetShield Bridge Conectado"}

        def start_port_scan(self, target, network_type="domestica"):
                if self._scanning:
                        return {"status": "error", "message": "Ya hay un escaneo en curso."}
                
                self._scanning = True
                thread = threading.Thread(target=self._run_scanner, args=(target, network_type))
                thread.daemon = True
                thread.start()
                return {"status": "success", "message": f"Escaneo iniciado en {target} (Red: {network_type})"}

        def _run_scanner(self, target, network_type):
                common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 8080]
                self._log_to_web(f"[SYSTEM] Analizando puertos comunes en {target} ({network_type})...")
                
                try:
                        ip = self._resolve_target(target)
                        if not ip:
                                return

                        open_ports = self._scan_ports(ip, common_ports)
                        
                        msg = "[SYSTEM] Escaneo finalizado. Analizando vulnerabilidades..." if self._lang == "es" else "[SYSTEM] Scan finished. Analyzing vulnerabilities..."
                        self._log_to_web(msg)
                        self._provide_recommendations(open_ports, network_type)

                except Exception as e:
                        self._log_to_web(f"[ERROR] {str(e)}", color="#ef4444")
                finally:
                        self._scanning = False

        def _resolve_target(self, target):
                try:
                        ip = socket.gethostbyname(target)
                        if ip != target:
                                msg = f"[SYSTEM] Objetivo resuelto a IP: {ip}" if self._lang == "es" else f"[SYSTEM] Target resolved to IP: {ip}"
                                self._log_to_web(msg)
                        return ip
                except socket.gaierror:
                        msg = f"[ERROR] No se pudo resolver el hostname: {target}" if self._lang == "es" else f"[ERROR] Could not resolve hostname: {target}"
                        self._log_to_web(msg, color="#ef4444")
                        self._scanning = False
                        return None

        def _scan_ports(self, ip, ports):
                open_ports = []
                for port in ports:
                        if not self._scanning: 
                                break
                        
                        if self._is_port_open(ip, port):
                                msg = f"[FOUND] Puerto {port}: ABIERTO" if self._lang == "es" else f"[FOUND] Port {port}: OPEN"
                                self._log_to_web(msg, color="#10b981")
                                open_ports.append(port)
                        
                        time.sleep(0.01)
                return open_ports

        def _is_port_open(self, ip, port):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.0)
                result = sock.connect_ex((ip, port))
                sock.close()
                return result == 0

        def _provide_recommendations(self, open_ports, network_type):
                if not open_ports:
                        self._log_to_web("[INFO] No se encontraron puertos abiertos. Tu sistema parece seguro frente a un escaneo rápido.", color="#38bdf8")
                        self._window.evaluate_js("updateReconChart(1, 0, 0);")
                        return

                self._log_to_web("<br>--- REPORTE DE SEGURIDAD ---", color="#f8fafc")
                stats = self._analyze_vulnerabilities(open_ports, network_type)
                
                should_alert = str(stats['critical'] > 0 and network_type in ["publica", "empresarial"]).lower()
                self._window.evaluate_js(f"updateReconChart({stats['safe']}, {stats['warning']}, {stats['critical']}, {should_alert});")

        def _analyze_vulnerabilities(self, open_ports, network_type):
                counts = {'safe': 0, 'warning': 0, 'critical': 0}
                for port in open_ports:
                        risk = self._check_port_risk(port, network_type)
                        counts[risk] += 1
                return counts

        def _check_port_risk(self, port, network_type):
                if port == 21:
                        self._log_to_web("[ALERTA] Puerto 21 (FTP) abierto. Protocolo no cifrado. Usa SFTP o FTPS en su lugar.", color="#f59e0b")
                        return 'warning'
                if port == 22:
                        return self._check_ssh_risk(network_type)
                if port == 23:
                        self._log_to_web("[CRÍTICO] Puerto 23 (Telnet) abierto. Protocolo obsoleto, TODO el tráfico es en texto plano. ¡CIÉRRALO INMEDIATAMENTE!", color="#ef4444")
                        return 'critical'
                if port == 80:
                        self._log_to_web("[INFO] Puerto 80 (HTTP) abierto. Considera forzar redirección a HTTPS (Puerto 443).", color="#10b981")
                        return 'safe'
                if port == 8080:
                        return self._check_alt_http_risk(network_type)
                if port in [135, 139, 445]:
                        return self._check_smb_risk(port, network_type)
                if port == 3306:
                        return self._check_db_risk(network_type)
                if port == 3389:
                        return self._check_rdp_risk(network_type)
                
                return 'safe'

        def _check_ssh_risk(self, network_type):
                if network_type == "publica":
                        self._log_to_web("[PELIGRO] Puerto 22 (SSH) expuesto en red pública. Altamente riesgoso. Deshabilita o cambia de puerto.", color="#ef4444")
                        return 'critical'
                self._log_to_web("[INFO] Puerto 22 (SSH) abierto. Asegúrate de usar claves públicas sólidas y deshabilitar acceso root por contraseña.", color="#10b981")
                return 'safe'

        def _check_alt_http_risk(self, network_type):
                if network_type == "publica":
                        self._log_to_web("[ALERTA] Puerto 8080 abierto. Asegura que el servicio web alternativo requiera autenticación.", color="#f59e0b")
                        return 'warning'
                return 'safe'

        def _check_smb_risk(self, port, network_type):
                if network_type == "publica":
                        self._log_to_web(f"[CRÍTICO] Puerto {port} (SMB/RPC) expuesto en red pública. ¡Riesgo altísimo de Ransomware! CIÉRRALO.", color="#ef4444")
                        return 'critical'
                self._log_to_web(f"[ALERTA] Puerto {port} (SMB/RPC) abierto. Deshabilita compartir archivos si no alojas recursos en tu red local.", color="#f59e0b")
                return 'warning'

        def _check_db_risk(self, network_type):
                if network_type != "empresarial":
                        self._log_to_web("[PELIGRO] Puerto 3306 (MySQL) abierto. Nunca expongas la base de datos a internet. Usa VPN local o SSH tunneling.", color="#ef4444")
                        return 'critical'
                return 'safe'

        def _check_rdp_risk(self, network_type):
                if network_type == "publica":
                        self._log_to_web("[CRÍTICO] Puerto 3389 (RDP) abierto. ¡RIESGO EXTREMO! Los ataques de fuerza bruta son constantes. Usa VPN.", color="#ef4444")
                        return 'critical'
                self._log_to_web("[ALERTA] Puerto 3389 (RDP) abierto. Implementa Autenticación a Nivel de Red (NLA) y cambia a un puerto no estándar.", color="#f59e0b")
                return 'warning'

        def start_web_audit(self, target, ownership="propio", use_proxy=False):
                if self._scanning:
                        return {"status": "error", "message": "Hay una tarea en curso."}
                
                self._scanning = True
                thread = threading.Thread(target=self._run_web_audit, args=(target, ownership, use_proxy))
                thread.daemon = True
                thread.start()
                return {"status": "success", "message": f"Auditoría web iniciada en {target}"}

        def _run_web_audit(self, target, ownership, use_proxy):
                self._log_to_web(f"[SYSTEM] Iniciando auditoría web en {target}...", dom_id="output-audit")
                self._warn_ethics(ownership)
                
                try:
                        if not self._setup_proxy_config(use_proxy):
                                return

                        url, base_url = self._normalize_url(target)
                        headers = self._audit_headers(url, ownership)
                        if headers:
                                self._fuzz_sensitive_files(url, base_url, ownership)

                        self._log_to_web("<br>[SYSTEM] Auditoría avanzada finalizada.", color="#f8fafc", dom_id="output-audit")
                except Exception as e:
                        self._log_to_web(f"[ERROR] Excepción inesperada: {str(e)}", color="#ef4444", dom_id="output-audit")
                finally:
                        self._scanning = False

        def _warn_ethics(self, ownership):
                if ownership == "ajeno":
                        self._log_to_web("<br><b>[ADVERTENCIA ÉTICA]</b>", color="#f59e0b", dom_id="output-audit")
                        msg = "Escanear o auditar dominios ajenos sin autorización expresa no es una buena práctica y puede considerarse una actividad hostil o ilegal dependiendo de tu jurisdicción. Por favor, asegúrate de tener permiso para analizar este objetivo."
                        self._log_to_web(msg, color="#f8fafc", dom_id="output-audit")
                        self._log_to_web("<br>", dom_id="output-audit")

        def _setup_proxy_config(self, use_proxy):
                from backend.proxy_manager import ProxyManager
                try:
                        if use_proxy:
                                selected_proxy = ProxyManager.setup_random_proxy()
                                msg = f"[SYSTEM] Rotación IP activada. Saltando por proxy: {selected_proxy}" if self._lang == "es" else f"[SYSTEM] IP Rotation Active. Hopping via proxy: {selected_proxy}"
                                self._log_to_web(msg, color="#38bdf8", dom_id="output-audit")
                        else:
                                ProxyManager.disable_proxy()
                        return True
                except Exception as e:
                        self._log_to_web(f"[ERROR] Falló la configuración del Proxy: {str(e)}", color="#ef4444", dom_id="output-audit")
                        self._scanning = False
                        return False

        def _normalize_url(self, target):
                url = target
                if not url.startswith("http://") and not url.startswith("https://"):
                        url = "http://" + url
                base_url = target.replace("http://", "").replace("https://", "").strip("/")
                return url, base_url

        def _audit_headers(self, url, ownership):
                self._log_to_web("[SYSTEM] Analizando parámetros de seguridad y cabeceras...", dom_id="output-audit")
                try:
                        req = urllib.request.Request(url, method="GET")
                        with urllib.request.urlopen(req, timeout=10) as response:
                                final_url = response.geturl()
                                headers = response.info()
                                
                                self._log_to_web(f"[FOUND] Respuesta desde: {final_url}", color="#10b981", dom_id="output-audit")
                                self._check_https_redirect(url, final_url)
                                self._check_exposure_headers(headers, ownership)
                                self._check_security_headers(headers, ownership)
                                return headers
                except urllib.error.URLError as e:
                        self._log_to_web(f"[ERROR] No se pudo establecer conexión inicial: {getattr(e, 'reason', str(e))}", color="#ef4444", dom_id="output-audit")
                        return None

        def _check_https_redirect(self, original_url, final_url):
                if original_url.startswith("http://") and final_url.startswith("https://"):
                        self._log_to_web("[OK] Redirección correcta a HTTPS detectada.", color="#10b981", dom_id="output-audit")
                elif final_url.startswith("http://"):
                        self._log_to_web("[CRÍTICO] El sitio resuelve a HTTP inseguro por defecto.", color="#ef4444", dom_id="output-audit")

        def _check_exposure_headers(self, headers, ownership):
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

        def _check_security_headers(self, headers, ownership):
                self._log_to_web("[SYSTEM] Verificando protección de cabeceras de seguridad...", color="#94a3b8", dom_id="output-audit")
                security_headers = {
                        "Strict-Transport-Security": "[HSTS] Falta configurar Strict-Transport-Security. Riesgo de ataques MITM y downgrade HTTP.",
                        "X-Frame-Options": "[Clickjacking] Falta X-Frame-Options. Tu sitio puede ser incrustado en iFrames maliciosos.",
                        "X-Content-Type-Options": "[MIME Sniffing] Falta X-Content-Type-Options: nosniff. Riesgo de inyección de recursos cruzados."
                }
                
                for header, warning in security_headers.items():
                        if not headers.get(header):
                                color = "#f59e0b" if ownership == "propio" else "#eab308"
                                label = "[ALERTA]" if ownership == "propio" else "[VULN]"
                                msg = f"{label} {warning}" if ownership == "propio" else f"{label} No tiene implementado: {header}"
                                self._log_to_web(msg, color=color, dom_id="output-audit")
                        else:
                                self._log_to_web(f"[OK] Cabecera {header} presente.", color="#10b981", dom_id="output-audit")

        def _fuzz_sensitive_files(self, url, base_url, ownership):
                self._log_to_web("<br>[SYSTEM] Buscando directorios y archivos comúnmente expuestos...", color="#94a3b8", dom_id="output-audit")
                sensitive_paths = ["/robots.txt", "/.git/config", "/admin/", "/phpinfo.php", "/.env"]
                protocol = "https://" if "https" in url else "http://"
                
                for path in sensitive_paths:
                        if not self._scanning: break
                        self._check_file_exposure(f"{protocol}{base_url}{path}", path, ownership)
                        time.sleep(0.1)

        def _check_file_exposure(self, full_url, path, ownership):
                try:
                        req = urllib.request.Request(full_url, method="HEAD")
                        with urllib.request.urlopen(req, timeout=3) as res:
                                if res.status in [200, 401, 403]:
                                        color = "#10b981" if res.status == 200 else "#eab308"
                                        self._log_to_web(f"[FOUND] Archivo detectado: {path} (HTTP {res.status})", color=color, dom_id="output-audit")
                                        if res.status == 200 and path != "/robots.txt" and ownership == "propio":
                                                self._log_to_web(f"&nbsp;&nbsp;↳ [CRÍTICO] ¡Estás exponiendo {path} públicamente! Bloquea el acceso o bórralo.", color="#ef4444", dom_id="output-audit")
                except urllib.error.URLError:
                        pass

        def _log_to_web(self, message, color=None, dom_id="output-recon"):
                clean_msg = re.sub(r'<[^>]+>', '', message).replace('&nbsp;', ' ')
                print(clean_msg)
                
                style = f'style="color:{color}"' if color else ""
                safe_message = message.replace("'", "\\'")
                js_code = f"document.getElementById('{dom_id}').innerHTML += '<br><span {style}>{safe_message}</span>';"
                self._window.evaluate_js(js_code)
                self._window.evaluate_js(f"const out = document.getElementById('{dom_id}'); if(out) out.scrollTop = out.scrollHeight;")

        def save_report(self, content, default_filename):
                try:
                        import webview
                        file_types = ('Archivos de Texto (*.txt)', 'Todos los archivos (*.*)')
                        result = self._window.create_file_dialog(webview.SAVE_DIALOG, directory='', save_filename=default_filename, file_types=file_types)
                        
                        if result and len(result) > 0:
                                with open(result[0], 'w', encoding='utf-8') as f:
                                        f.write(content)
                                return {"status": "success", "filepath": result[0]}
                        return {"status": "cancelled", "message": "Operación cancelada por el usuario"}
                except Exception as e:
                        return {"status": "error", "message": str(e)}

        def start_fuzzing(self, target):
                if self._scanning:
                        return {"status": "error", "message": "Hay una tarea en curso."}
                
                self._scanning = True
                thread = threading.Thread(target=self._run_fuzzing, args=(target,))
                thread.daemon = True
                thread.start()
                return {"status": "success", "message": f"Fuzzing iniciado en {target}"}

        def _run_fuzzing(self, target):
                url, _ = self._normalize_url(target)
                if not url.endswith("/"): url += "/"
                self._log_to_web(f"[SYSTEM] Iniciando motor de Fuzzing en {url}...", dom_id="output-fuzz")
                
                dictionary = ["admin", "login", "wp-admin", "wp-login.php", "backup", "db", "db.sql", "backup.zip", "test", ".env", ".git/config", "robots.txt", "phpinfo.php", "api", "v1", "swagger.json", "sitemap.xml", "config.php", "server-status"]
                
                try:
                        found_count = 0
                        for path in dictionary:
                                if not self._scanning: break
                                if self._fuzz_path(url + path, path):
                                        found_count += 1
                                time.sleep(0.05)
                        self._log_to_web(f"<br>[SYSTEM] Fuzzing finalizado. {found_count} rutas encontradas.", color="#38bdf8", dom_id="output-fuzz")
                except Exception as e:
                        self._log_to_web(f"[ERROR] {str(e)}", color="#ef4444", dom_id="output-fuzz")
                finally:
                        self._scanning = False

        def _fuzz_path(self, full_url, path):
                req = urllib.request.Request(full_url, method="HEAD")
                try:
                        with urllib.request.urlopen(req, timeout=3) as res:
                                if res.status in [200, 301, 302, 401, 403]:
                                        color = "#10b981" if res.status == 200 else "#f59e0b"
                                        self._log_to_web(f"[FOUND] /{path} (HTTP {res.status})", color=color, dom_id="output-fuzz")
                                        return True
                except urllib.error.URLError as e:
                        if hasattr(e, 'code') and e.code in [401, 403]:
                                self._log_to_web(f"[FOUND] /{path} (HTTP {e.code} Forbidden/Unauthorized)", color="#f59e0b", dom_id="output-fuzz")
                                return True
                return False

        def start_ping_sweep(self, _range):
                if self._scanning:
                        return {"status": "error", "message": "Hay una tarea en curso."}
                        
                self._scanning = True
                thread = threading.Thread(target=self._run_ping_sweep, args=(_range,))
                thread.daemon = True
                thread.start()
                return {"status": "success", "message": f"Ping Sweep iniciado en {_range}"}

        def _run_ping_sweep(self, network_range):
                self._log_to_web(f"[SYSTEM] Iniciando descubrimiento en red {network_range}...", dom_id="output-ping")
                try:
                        net = ipaddress.ip_network(network_range, strict=False)
                        hosts = list(net.hosts())
                        
                        if len(hosts) > 512:
                                self._log_to_web("[ERROR] Rango muy grande. Limítalo a un /24 o menor.", color="#ef4444", dom_id="output-ping")
                                self._scanning = False
                                return
                                
                        found = self._perform_sweep(hosts)
                        self._log_to_web(f"<br>[SYSTEM] Rastreo finalizado. {found} equipos encontrados.", color="#38bdf8", dom_id="output-ping")
                except Exception as e:
                        self._log_to_web(f"[ERROR] {str(e)}", color="#ef4444", dom_id="output-ping")
                finally:
                        self._scanning = False

        def _perform_sweep(self, hosts):
                found = 0
                oper_sys = platform.system().lower()
                for ip in hosts:
                        if not self._scanning: break
                        if self._ping(str(ip), oper_sys):
                                self._log_to_web(f"[FOUND] Equipo activo: {ip}", color="#10b981", dom_id="output-ping")
                                found += 1
                return found

        def _ping(self, ip_str, oper_sys):
                cmd = ["ping", "-n", "1", "-w", "200", ip_str] if oper_sys == "windows" else ["ping", "-c", "1", "-W", "1", ip_str]
                try:
                        return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
                except:
                        return False

        def start_local_audit(self):
                if self._scanning:
                        return {"status": "error", "message": "Hay una tarea en curso."}
                self._scanning = True
                threading.Thread(target=self._run_local_audit).start()
                return {"status": "success", "message": "Auditoría Local Iniciada."}
                
        def _run_local_audit(self):
                self._log_to_web("[SYSTEM] Evaluando host local...", dom_id="output-local")
                if platform.system().lower() != "windows":
                        self._log_to_web("[ALERTA] Este módulo de auditoría local está optimizado para Windows.", color="#f59e0b", dom_id="output-local")
                        self._scanning = False
                        return
                        
                try:
                        self._check_local_firewall()
                        self._check_local_defender()
                        self._check_local_privileges()
                        self._log_to_web("<br>[SYSTEM] Auditoría Local Finalizada.", color="#f8fafc", dom_id="output-local")
                except Exception as e:
                        self._log_to_web(f"[ERROR] {str(e)}", color="#ef4444", dom_id="output-local")
                finally:
                        self._scanning = False

        def _check_local_firewall(self):
                self._log_to_web("<br>[*] Verificando Perfiles de Windows Firewall...", color="#38bdf8", dom_id="output-local")
                res = subprocess.run('powershell "Get-NetFirewallProfile | Format-Table Name, Enabled"', capture_output=True, text=True, shell=True)
                if "False" in res.stdout:
                        self._log_to_web("[CRÍTICO] ¡Uno o más perfiles del Firewall están APAGADOS!", color="#ef4444", dom_id="output-local")
                else:
                        self._log_to_web("[OK] Perfiles de Firewall activos.", color="#10b981", dom_id="output-local")

        def _check_local_defender(self):
                self._log_to_web("<br>[*] Verificando Estado de Windows Defender...", color="#38bdf8", dom_id="output-local")
                res = subprocess.run('powershell "Get-MpComputerStatus | Select-Object -Property RealTimeProtectionEnabled"', capture_output=True, text=True, shell=True)
                if "False" in res.stdout:
                        self._log_to_web("[CRÍTICO] ¡Protección en Tiempo Real DESACTIVADA!", color="#ef4444", dom_id="output-local")
                else:
                        self._log_to_web("[OK] Protección en Tiempo Real Activa.", color="#10b981", dom_id="output-local")

        def _check_local_privileges(self):
                self._log_to_web("<br>[*] Verificando Nivel de Privilegios Locales...", color="#38bdf8", dom_id="output-local")
                if ctypes.windll.shell32.IsUserAnAdmin() != 0:
                        self._log_to_web("[ADVERTENCIA] Estás corriendo como Administrador Global.", color="#f59e0b", dom_id="output-local")
                else:
                        self._log_to_web("[OK] Corriendo en modo Usuario Estándar.", color="#10b981", dom_id="output-local")