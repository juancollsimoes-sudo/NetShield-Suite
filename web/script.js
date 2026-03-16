function showSection(sectionId) {
        // Ocultar todas las secciones
        document.querySelectorAll('.section').forEach(sec => {
                sec.style.display = 'none';
                sec.classList.remove('active-section');
        });

        // Mostrar la sección seleccionada
        const targetSection = document.getElementById(sectionId);
        if (targetSection) {
                targetSection.style.display = 'block';
                targetSection.classList.add('active-section');
        }

        updateSidebarLinks(sectionId);
}

function updateSidebarLinks(sectionId) {
        document.querySelectorAll('.nav-item').forEach(item => {
                item.classList.remove('active');
                const onclickAttr = item.getAttribute('onclick');
                if (onclickAttr && onclickAttr.includes(sectionId)) {
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

        const response = await pywebview.api.start_port_scan(target, networkType);
        handleApiResponse(response, output);
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

        const response = await pywebview.api.start_web_audit(target, ownership, useProxy);
        handleApiResponse(response, output);
}

async function startFuzzing() {
        const target = document.getElementById('target-fuzz').value;
        const output = document.getElementById('output-fuzz');

        if (!target) {
                output.innerHTML += `<br><span style="color:var(--danger)">[ERROR] Introduce una URL válida.</span>`;
                return;
        }

        const response = await pywebview.api.start_fuzzing(target);
        handleApiResponse(response, output);
}

async function startPingSweep() {
        const target = document.getElementById('target-ping').value;
        const output = document.getElementById('output-ping');

        if (!target) {
                output.innerHTML += `<br><span style="color:var(--danger)">[ERROR] Introduce un rango IP válido.</span>`;
                return;
        }

        const response = await pywebview.api.start_ping_sweep(target);
        handleApiResponse(response, output);
}

async function startLocalAudit() {
        const output = document.getElementById('output-local');
        output.innerHTML = `[SYSTEM] Iniciando auditoría local...`;

        const response = await pywebview.api.start_local_audit();
        handleApiResponse(response, output);
}

function handleApiResponse(response, outputElement) {
        if (response && response.status === "error") {
                outputElement.innerHTML += `<br><span style="color:var(--danger)">${response.message}</span>`;
        }
}

async function exportReport(elementId, defaultName) {
        const outputDiv = document.getElementById(elementId);
        if (!outputDiv) return;

        const content = formatOutputForExport(outputDiv.innerHTML);
        if (!content) {
                alert("No hay resultados suficientes para exportar.");
                return;
        }

        const result = await pywebview.api.save_report(content, defaultName);
        handleExportResult(result);
}

function formatOutputForExport(html) {
        let text = html.replace(/<br\s*[\/]?>/gi, "\n");
        text = text.replace(/<[^>]*>?/gm, "").trim();
        
        const isPlaceholder = text.includes("esperando objetivo") || text.includes("listo...");
        return (!text || isPlaceholder) ? null : text;
}

function handleExportResult(result) {
        if (result && result.status === "success") {
                alert("Reporte guardado exitosamente en: \n" + result.filepath);
        } else if (result && result.status === "error") {
                alert("Error al guardar: " + result.message);
        }
}

let severityChart = null;

function updateReconChart(safe, warning, critical, shouldAlert) {
        const ctx = document.getElementById('reconChart').getContext('2d');
        const container = document.getElementById('chart-container');
        
        container.style.display = 'flex';
        toggleEmergencyAlert(shouldAlert);
        
        if (severityChart) {
                severityChart.destroy();
        }
        
        createSeverityChart(ctx, safe, warning, critical);
}

function toggleEmergencyAlert(show) {
        const alertBox = document.getElementById('emergency-alert');
        if (alertBox) {
                alertBox.style.display = show ? 'block' : 'none';
        }
}

function createSeverityChart(ctx, safe, warning, critical) {
        const labels = currentLang === 'es' ? ['Seguro', 'Advertencia', 'Crítico'] : ['Safe', 'Warning', 'Critical'];
        const textColor = getComputedStyle(document.documentElement).getPropertyValue('--text-main').trim() || '#f8fafc';

        severityChart = new Chart(ctx, {
                type: 'doughnut',
                data: {
                        labels: labels,
                        datasets: [{
                                data: [safe, warning, critical],
                                backgroundColor: ['#10b981', '#f59e0b', '#ef4444'],
                                borderColor: '#1e293b',
                                borderWidth: 2
                        }]
                },
                options: {
                        responsive: true,
                        plugins: {
                                legend: {
                                        position: 'bottom',
                                        labels: { color: textColor }
                                }
                        }
                }
        });
}