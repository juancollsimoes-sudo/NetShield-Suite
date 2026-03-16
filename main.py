import sys
import os
import webview
from backend.api import Api

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

def start_app():
    # Instanciamos la API
    api = Api()
    
    # Creamos la ventana de NetShield
    window = webview.create_window(
        title='NetShield Suite v1.0',
        url=resource_path('web/index.html'),
        js_api=api,
        width=1000,
        height=700,
        resizable=True,
        background_color='#0f172a' # Dark Slate
    )
    
    # Pasamos la referencia de la ventana a la API
    api.set_window(window)

if __name__ == '__main__':
    start_app()
    # Agregamos gui='edgehtml' o gui='cef' para evitar la descarga de la DLL
    webview.start(debug=False, gui='edgehtml')