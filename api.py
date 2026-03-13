class Api:
    def __init__(self):
        self._window = None

    def set_window(self, window):
        self._window = window

    def check_connection(self):
        """Método de prueba para verificar la comunicación."""
        return {"status": "success", "message": "NetShield Bridge Conectado"}