
import asyncio
import random
import logging
import requests
from typing import List, Optional

logger = logging.getLogger(__name__)

class LocalProxyRotator:
    """
    Manages local proxy rotation for Axiom requests.
    Rotates through a list of local ports (e.g. 10000-10100) and patches requests 
    to use the current proxy for axiom.trade domains.
    """
    def __init__(self, port_range: range = range(10000, 10100), rotation_interval: float = 3.0):
        self.proxy_ports = list(port_range)
        self.rotation_interval = rotation_interval
        self._current_proxy_port = random.choice(self.proxy_ports)
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._original_session_request = requests.Session.request

    def get_current_proxy(self):
        """Returns the current proxy configuration."""
        return {
            "http": f"http://127.0.0.1:{self._current_proxy_port}",
            "https": f"http://127.0.0.1:{self._current_proxy_port}",
        }

    def _rotate_proxy(self):
        """Selects a new random proxy port."""
        self._current_proxy_port = random.choice(self.proxy_ports)
        logger.debug(f"Proxy rotated to port {self._current_proxy_port}")

    async def _rotation_loop(self):
        """Background task to rotate proxy periodically."""
        while self._running:
            await asyncio.sleep(self.rotation_interval)
            self._rotate_proxy()

    def start(self):
        """Starts the rotation task and installs the patch."""
        if self._running:
            return
        self._running = True
        self.install_requests_proxy_patch()
        self._task = asyncio.create_task(self._rotation_loop())
        logger.info(f"LocalProxyRotator started with {len(self.proxy_ports)} ports. interval={self.rotation_interval}s")

    def stop(self):
        """Stops the rotation task and restores original requests behavior."""
        self._running = False
        if self._task:
            self._task.cancel()
        requests.Session.request = self._original_session_request
        logger.info("LocalProxyRotator stopped.")

    def install_requests_proxy_patch(self):
        """Patches requests.Session.request to use the rotating proxy for axiom.trade."""
        # Store original if not already stored (in case of multiple calls)
        # self._original_session_request is set in __init__
        
        rotator = self # closure for the patched function

        def _patched_request(session_self, method, url, **kwargs):
            if "axiom.trade" in (url or ""):
                kwargs = dict(kwargs)
                kwargs.setdefault("proxies", {})
                kwargs["proxies"].update(rotator.get_current_proxy())
            return rotator._original_session_request(session_self, method, url, **kwargs)

        requests.Session.request = _patched_request
