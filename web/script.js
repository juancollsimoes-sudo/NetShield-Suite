function showSection(section) {
    console.log("Cambiando a sección: " + section);
    // Lógica para cambiar de pestañas en el futuro
}

async function startScan() {
    const target = document.getElementById('target').value;
    const output = document.getElementById('output');

    if (!target) {
        output.innerHTML += `<br><span style="color:var(--danger)">[ERROR] Introduce un objetivo válido.</span>`;
        return;
    }

    output.innerHTML += `<br>[INFO] Iniciando escaneo en: ${target}...`;

    // Llamada al puente de Python (Api.check_connection que hicimos antes)
    const response = await pywebview.api.check_connection();
    output.innerHTML += `<br>[BRIDGE] ${response.message}`;
}