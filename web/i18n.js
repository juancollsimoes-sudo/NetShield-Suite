const translations = {
    es: {
        nav_recon: "Reconocimiento",
        nav_audit: "Auditoría Web",
        nav_fuzz: "Fuzzing de Directorios",
        nav_ping: "Ping Sweep",
        nav_local: "Salud del Sistema (Local)",
        nav_settings: "Configuración",
        
        chart_title: "Resumen de Severidad",

        title_recon: "Escáner de Puertos",
        target_recon_ph: "IP o Dominio (ej: 127.0.0.1)",
        net_home: "Red Doméstica",
        net_corp: "Red Empresarial",
        net_pub: "Red Pública",
        btn_scan: "INICIAR ESCANEO",
        
        alert_title: "⚠️ ALERTA DE EMERGENCIA ⚠️",
        alert_text: "Se han detectado puertos CRÍTICOS expuestos en una red pública o empresarial. Tu equipo es altamente vulnerable a ataques directos.",

        title_audit: "Auditoría Web",
        target_audit_ph: "Dominio o URL (ej: example.com)",
        own_yes: "Dominio Propio",
        own_no: "Dominio Ajeno",
        proxy_label: "Activar Rotación de Proxy Automática (Ocultar mi IP)",
        btn_audit: "INICIAR AUDITORÍA",

        title_fuzz: "Fuzzing de Directorios",
        target_fuzz_ph: "URL Base (ej: http://example.com/)",
        btn_fuzz: "INICIAR FUZZING",

        title_ping: "Ping Sweep (Rango IP)",
        target_ping_ph: "Rango IP (ej: 192.168.1.0/24)",
        btn_ping: "DESCUBRIR EQUIPOS",

        title_local: "Auditoría Local del Sistema",
        desc_local: "Analiza la configuración de seguridad actual de tu propio equipo Windows (Firewall, Antivirus, etc).",
        btn_local: "ANALIZAR MI PC",

        title_settings: "Configuración",
        label_lang: "Idioma / Language:",
        label_theme: "Tema de la Interfaz:",
        theme_inter: "Intermedio (Original)",
        theme_dark: "Oscuro (Hacker)",
        theme_light: "Claro",
        
        btn_report: "GUARDAR REPORTE",

        modal_title: "ADVERTENCIA: USO ÉTICO",
        modal_text1: "NetShield Suite es una herramienta diseñada EXCLUSIVAMENTE para fines educativos y para auditar sistemas y redes que te pertenecen o para los cuales tienes autorización explícita.",
        modal_text2: "Cualquier uso de esta herramienta contra objetivos de terceros sin permiso puede considerarse ilegal y está bajo tu entera responsabilidad. El autor no se hace responsable del mal uso de este software.",
        btn_accept: "ACEPTO, COMENZAR",
        
        legal_title: "Términos y Condiciones Legales",
        legal_text: "Al utilizar NetShield Suite, usted se compromete a cumplir con todas las leyes locales, estatales, federales e internacionales aplicables. En los Estados Unidos de América, el acceso no autorizado a sistemas informáticos está estrictamente prohibido y penado por la Ley de Fraude y Abuso Informático (Computer Fraud and Abuse Act - 18 U.S.C. § 1030). Escanear, auditar o realizar fuzzing contra redes empresariales, gubernamentales o privadas sin consentimiento expreso por escrito de los propietarios del sistema constituye un delito federal que puede resultar en multas severas y penas de prisión. Usted asume todos los riesgos y responsabilidades legales derivados de sus acciones usando este software."
    },
    en: {
        nav_recon: "Reconnaissance",
        nav_audit: "Web Audit",
        nav_fuzz: "Directory Fuzzing",
        nav_ping: "Ping Sweep",
        nav_local: "System Health (Local)",
        nav_settings: "Settings",
        
        chart_title: "Severity Summary",

        title_recon: "Port Scanner",
        target_recon_ph: "IP or Domain (e.g., 127.0.0.1)",
        net_home: "Home Network",
        net_corp: "Corporate Network",
        net_pub: "Public Network",
        btn_scan: "START SCAN",

        alert_title: "⚠️ EMERGENCY ALERT ⚠️",
        alert_text: "CRITICAL ports have been detected exposed on a public or corporate network. Your machine is highly vulnerable to direct attacks.",

        title_audit: "Web Audit",
        target_audit_ph: "Domain or URL (e.g., example.com)",
        own_yes: "My Domain",
        own_no: "Third-party Domain",
        proxy_label: "Enable Automatic Proxy Rotation (Hide my IP)",
        btn_audit: "START AUDIT",

        title_fuzz: "Directory Fuzzing",
        target_fuzz_ph: "Base URL (e.g., http://example.com/)",
        btn_fuzz: "START FUZZING",

        title_ping: "Ping Sweep (IP Range)",
        target_ping_ph: "IP Range (e.g., 192.168.1.0/24)",
        btn_ping: "DISCOVER HOSTS",

        title_local: "Local System Audit",
        desc_local: "Analyze the current security configuration of your own Windows machine (Firewall, Antivirus, etc).",
        btn_local: "ANALYZE MY PC",

        title_settings: "Settings",
        label_lang: "Language / Idioma:",
        label_theme: "Interface Theme:",
        theme_inter: "Intermediate (Original)",
        theme_dark: "Dark (Hacker)",
        theme_light: "Light",

        btn_report: "SAVE REPORT",

        modal_title: "WARNING: ETHICAL USE ONLY",
        modal_text1: "NetShield Suite is a tool designed EXCLUSIVELY for educational purposes and for auditing systems and networks that belong to you or for which you have explicit authorization.",
        modal_text2: "Any use of this tool against third-party targets without permission may be considered illegal and is your sole responsibility. The author is not responsible for the misuse of this software.",
        btn_accept: "I ACCEPT, START",
        
        legal_title: "Legal Terms and Conditions",
        legal_text: "By using NetShield Suite, you agree to comply with all applicable local, state, federal, and international laws. In the United States of America, unauthorized access to computer systems is strictly prohibited and punishable under the Computer Fraud and Abuse Act (18 U.S.C. § 1030). Scanning, auditing, or fuzzing corporate, government, or private networks without express written consent from the system owners constitutes a federal crime that can result in severe fines and imprisonment. You assume all legal risks and responsibilities arising from your actions using this software."
    }
};

let currentLang = 'es';

function setLanguage(lang) {
    currentLang = lang;
    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        if (translations[lang][key]) {
            if (el.tagName === 'INPUT' && el.type === 'text') {
                el.placeholder = translations[lang][key];
            } else {
                el.innerText = translations[lang][key];
            }
        }
    });
    
    // Also notify Python backend of the language change so python-generated strings can be localized too
    if (window.pywebview && window.pywebview.api) {
        window.pywebview.api.set_language(lang);
    }
}

function acceptDisclaimer() {
    document.getElementById('disclaimer-modal').style.display = 'none';
}

function setTheme(theme) {
    if(theme === 'intermedio') {
        document.documentElement.removeAttribute('data-theme');
    } else {
        document.documentElement.setAttribute('data-theme', theme);
    }
}

// Auto-init based on saved preference or default
window.addEventListener('pywebviewready', function() {
    setLanguage(currentLang);
    setTheme('intermedio');
});
