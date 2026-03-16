function showSection(sectionId) {
    console.log("Cambiando a sección: " + sectionId);

    // Ocultar todas las secciones
    const sections = document.querySelectorAll('.section');
    sections.forEach(sec => {
        sec.style.display = 'none';
        sec.classList.remove('active-section');
    });

    // Mostrar la sección seleccionada
    const targetSection = document.getElementById(sectionId);
    if (targetSection) {
        targetSection.style.display = 'block';
        targetSection.classList.add('active-section');
    }

    // Actualizar estilo del menú lateral
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        item.classList.remove('active');
        if (item.getAttribute('onclick') && item.getAttribute('onclick').includes(sectionId)) {
            item.classList.add('active');
        }
    });
}

async function startScan() {
    const target = document.getElementById('target-recon').value;
    const networkType = document.getElementById('network-type').value;
    const output = document.getElementById('output-recon');

    if (!target) {
        output.innerHTML += `<br><span style="color:var(--danger)">[ERROR] Introduce un objetivo válido.</span>`;
        return;
    }

    // Llamamos al escáner en Python pasando también el tipo de red
    const response = await pywebview.api.start_port_scan(target, networkType);

    if (response.status === "error") {
        output.innerHTML += `<br><span style="color:var(--danger)">${response.message}</span>`;
    }
}

async function startWebAudit() {
    const target = document.getElementById('target-audit').value;
    const ownership = document.getElementById('domain-ownership').value;
    const useProxy = document.getElementById('proxy-audit').checked;
    const output = document.getElementById('output-audit');

    if (!target) {
        output.innerHTML += `<br><span style="color:var(--danger)">[ERROR] Introduce un dominio válido.</span>`;
        return;
    }

    // Llamamos la auditoría en Python (useProxy = booleano)
    const response = await pywebview.api.start_web_audit(target, ownership, useProxy);

    if (response.status === "error") {
        output.innerHTML += `<br><span style="color:var(--danger)">${response.message}</span>`;
    }
}

async function startFuzzing() {
    const target = document.getElementById('target-fuzz').value;
    const output = document.getElementById('output-fuzz');

    if (!target) {
        output.innerHTML += `<br><span style="color:var(--danger)">[ERROR] Introduce una URL válida.</span>`;
        return;
    }

    const response = await pywebview.api.start_fuzzing(target);
    if (response.status === "error") {
        output.innerHTML += `<br><span style="color:var(--danger)">${response.message}</span>`;
    }
}

async function startPingSweep() {
    const target = document.getElementById('target-ping').value;
    const output = document.getElementById('output-ping');

    if (!target) {
        output.innerHTML += `<br><span style="color:var(--danger)">[ERROR] Introduce un rango IP válido.</span>`;
        return;
    }

    const response = await pywebview.api.start_ping_sweep(target);
    if (response.status === "error") {
        output.innerHTML += `<br><span style="color:var(--danger)">${response.message}</span>`;
    }
}

async function startLocalAudit() {
    const output = document.getElementById('output-local');
    output.innerHTML = `[SYSTEM] Iniciando auditoría local...`;

    // Llamamos a la API de python
    const response = await pywebview.api.start_local_audit();

    if (response && response.status === "error") {
        output.innerHTML += `<br><span style="color:var(--danger)">${response.message}</span>`;
    }
}

async function exportReport(elementId, defaultName) {
    const outputDiv = document.getElementById(elementId);
    if (!outputDiv) return;

    // Obtener texto sin etiquetas HTML para el reporte (removiendo <br> y estilos)
    let content = outputDiv.innerHTML;
    content = content.replace(/<br\s*[\/]?>/gi, "\n"); // Reemplazar <br> por saltos de línea
    content = content.replace(/<[^>]*>?/gm, ""); // Quitar tags HTML restantes (span, b, etc)
    content = content.trim();

    if (!content || content.includes("esperando objetivo") || content.includes("listo...")) {
        alert("No hay resultados suficientes para exportar.");
        return;
    }

    // Llamamos a la API para abrir el diálogo de guardar archivo
    const result = await pywebview.api.save_report(content, defaultName);
    if (result && result.status === "success") {
        alert("Reporte guardado exitosamente en: \n" + result.filepath);
    } else if (result && result.status === "error") {
        alert("Error al guardar: " + result.message);
    }
}

// Chart.js Integration
let severityChart = null;

function updateReconChart(safe, warning, critical, shouldAlert) {
    const ctx = document.getElementById('reconChart').getContext('2d');
    const container = document.getElementById('chart-container');
    const alertBox = document.getElementById('emergency-alert');
    
    // Show chart container
    container.style.display = 'flex';
    
    // Manage emergency alert box
    if (shouldAlert && alertBox) {
        alertBox.style.display = 'block';
    } else if (alertBox) {
        alertBox.style.display = 'none';
    }
    
    if (severityChart) {
        severityChart.destroy();
    }
    
    const labels = currentLang === 'es' ? ['Seguro', 'Advertencia', 'Crítico'] : ['Safe', 'Warning', 'Critical'];
    
    severityChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: [safe, warning, critical],
                backgroundColor: [
                    '#10b981', // Safe (Green)
                    '#f59e0b', // Warning (Orange)
                    '#ef4444'  // Critical (Red)
                ],
                borderColor: '#1e293b',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: getComputedStyle(document.documentElement).getPropertyValue('--text-main').trim() || '#f8fafc' }
                }
            }
        }
    });
}