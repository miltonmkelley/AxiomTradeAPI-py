import json
import logging
import asyncio
import aiohttp
from typing import Optional, Callable, Dict, Any

class AxiomTradeWebSocketClient:    
    def __init__(self, auth_manager, log_level=logging.INFO) -> None:
        self.ws_url = "wss://cluster-usc2.axiom.trade/"
        self.ws_url_token_price = "wss://socket8.axiom.trade/"
        self.ws: Optional[aiohttp.ClientWebSocketResponse] = None
        self.session: Optional[aiohttp.ClientSession] = None
        
        if not auth_manager:
            raise ValueError("auth_manager is required and must be an authenticated AuthManager instance")
        
        self.auth_manager = auth_manager
        
        # Setup logging
        self.logger = logging.getLogger("AxiomTradeWebSocket")
        self.logger.setLevel(log_level)
        
        # Create console handler if none exists
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            handler.setLevel(log_level)
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
        
        self._callbacks: Dict[str, Callable] = {}

    async def connect(self, is_token_price: bool = False) -> bool:
        """Connect to the WebSocket server using aiohttp."""
        # Ensure we have valid authentication
        if not self.auth_manager.ensure_valid_authentication():
            self.logger.error("WebSocket authentication failed - unable to obtain valid tokens")
            return False
        
        # Get tokens from auth manager
        tokens = self.auth_manager.get_tokens()
        if not tokens:
            self.logger.error("No authentication tokens available")
            return False
        
        headers = {
            'Origin': 'https://axiom.trade',
            'Cache-Control': 'no-cache',
            'Accept-Language': 'en-US,en;q=0.9,es;q=0.8',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        }
        
        # Add authentication cookies
        cookie_header = f"auth-access-token={tokens.access_token}; auth-refresh-token={tokens.refresh_token}"
        headers["Cookie"] = cookie_header
        
        self.logger.debug(f"Connecting to WebSocket with headers: {headers}")
        
        # Get proxy if configured
        proxy = self.auth_manager.proxy
        if proxy:
            self.logger.info(f"Using proxy for WebSocket: {proxy.split('@')[-1] if '@' in proxy else proxy}")

        try:
            if not self.session:
                self.session = aiohttp.ClientSession()

            if is_token_price:
                current_url = self.ws_url_token_price
            else:
                current_url = self.ws_url
            
            # Try the primary URL first
            self.logger.info(f"Attempting to connect to WebSocket: {current_url}")
            
            self.ws = await self.session.ws_connect(
                current_url,
                headers=headers,
                proxy=proxy,
                heartbeat=30.0,
                autoping=True
            )
            self.logger.info("Connected to WebSocket server")
            return True

        except Exception as e:
            self.logger.error(f"Failed to connect to WebSocket: {e}")
            # Try alternative URL if the primary one fails
            if not is_token_price and "cluster-usc2" in self.ws_url:
                try:
                    alternative_url = "wss://cluster3.axiom.trade/"
                    self.logger.info(f"Trying alternative WebSocket URL: {alternative_url}")
                    self.ws = await self.session.ws_connect(
                        alternative_url,
                        headers=headers,
                        proxy=proxy,
                        heartbeat=30.0,
                        autoping=True
                    )
                    self.logger.info("Connected to alternative WebSocket server")
                    return True
                except Exception as e2:
                    self.logger.error(f"Alternative WebSocket connection also failed: {e2}")
            return False

    async def subscribe_new_tokens(self, callback: Callable[[Dict[str, Any]], None]):
        """Subscribe to new token updates."""
        if not self.ws:
            if not await self.connect():
                return False

        self._callbacks["new_pairs"] = callback
        
        try:
            await self.ws.send_json({
                "action": "join",
                "room": "new_pairs"
            })
            self.logger.info("Subscribed to new token updates")
            return True
        except Exception as e:
            self.logger.error(f"Failed to subscribe to new tokens: {e}")
            return False

    async def subscribe_token_price(self, token: str, callback: Callable[[Dict[str, Any]], None]):
        """Subscribe to token price updates."""
        if not self.ws:
            if not await self.connect(is_token_price=True):
                return False

        self._callbacks[f"token_price_{token}"] = callback
        
        try:
            await self.ws.send_json({
                "action": "join",
                "room": token
            })
            self.logger.info(f"Subscribed to token price updates for {token}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to subscribe to token price: {e}")
            return False
        
    async def subscribe_wallet_transactions(self, wallet_address: str, callback: Callable[[Dict[str, Any]], None]):
        """Subscribe to wallet transaction updates."""
        if not self.ws:
            if not await self.connect():
                return False

        self._callbacks[f"wallet_transactions_{wallet_address}"] = callback
        
        try:
            await self.ws.send_json({
                "action": "join",
                "room": f"v:{wallet_address}"
            })
            self.logger.info(f"Subscribed to wallet transactions for {wallet_address}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to subscribe to wallet transactions: {e}")
            return False

    async def _message_handler(self):
        """Handle incoming WebSocket messages."""
        try:
            async for msg in self.ws:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                        
                        # Handle new token updates
                        if "new_pairs" in self._callbacks and data.get("room") == "new_pairs":
                            await self._callbacks["new_pairs"](data)
                        
                        # Handle token price updates
                        for key, callback in self._callbacks.items():
                            if key.startswith("token_price_"):
                                token = key.replace("token_price_", "")
                                if data.get("room") == token and data.get("content"):
                                    await callback(data.get("content"))
                                
                        # Handle wallet transactions
                        for key, callback in self._callbacks.items():
                            if key.startswith("wallet_transactions_"):
                                wallet_address = key.replace("wallet_transactions_", "")
                                if data.get("room") == f"v:{wallet_address}" and data.get("content"):
                                    await callback(data.get("content"))
                        
                    except json.JSONDecodeError:
                        self.logger.error(f"Failed to parse WebSocket message: {msg.data}")
                    except Exception as e:
                        self.logger.error(f"Error handling WebSocket message: {e}")
                        
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    self.logger.error(f'WebSocket connection closed with exception {self.ws.exception()}')
                    break
                    
        except Exception as e:
            self.logger.error(f"WebSocket message handler error: {e}")

    async def start(self):
        """Start the WebSocket client and message handler."""
        if not self.ws:
            if not await self.connect():
                return
        
        await self._message_handler()

    async def close(self):
        """Close the WebSocket connection and session."""
        if self.ws:
            await self.ws.close()
        if self.session:
            await self.session.close()
        self.logger.info("WebSocket connection closed")
