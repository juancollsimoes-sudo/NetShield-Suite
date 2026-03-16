import urllib.request
import urllib.error
import random

class ProxyManager:
    # Una lista pequeña de prueba para Proxies gratuitos HTTP/HTTPS
    # (En un programa comercial esto se consumiría de una API viva debido a que los proxies mueren rápido)
    PROXIES_LIST = [
        "http://34.125.131.250:80",
        "http://20.24.43.214:80",
        "http://149.28.140.10:8080",
        "http://45.79.20.155:8080",
        "http://198.199.86.11:8080",
        "http://34.148.118.29:80"
    ]

    @staticmethod
    def setup_random_proxy():
        """
        Elige un proxy al azar de la lista y enruta todo el tráfico a través de él.
        """
        selected_proxy = random.choice(ProxyManager.PROXIES_LIST)
        
        proxy_handler = urllib.request.ProxyHandler({
            'http': selected_proxy,
            'https': selected_proxy
        })
        opener = urllib.request.build_opener(proxy_handler)
        urllib.request.install_opener(opener)
        
        return selected_proxy

    @staticmethod
    def disable_proxy():
        """Restaura la conexión directa sin proxies."""
        proxy_handler = urllib.request.ProxyHandler({})
        opener = urllib.request.build_opener(proxy_handler)
        urllib.request.install_opener(opener)
