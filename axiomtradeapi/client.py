from __future__ import annotations
import requests
import json
import base64
import logging
from typing import Dict, Optional, List, Union, TYPE_CHECKING
from .auth.auth_manager import AuthManager, create_authenticated_session
from .content.endpoints import Endpoints
from .websocket._client import AxiomTradeWebSocketClient

# Trading-related imports
if TYPE_CHECKING:
    from solders.keypair import Keypair
    from solders.transaction import Transaction
    from solders.pubkey import Pubkey

try:
    from solders.keypair import Keypair
    from solders.transaction import Transaction
    from solders.pubkey import Pubkey
    SOLDERS_AVAILABLE = True
except ImportError:
    SOLDERS_AVAILABLE = False
    Keypair = None
    Transaction = None
    Pubkey = None

try:
    import base58
    BASE58_AVAILABLE = True
except ImportError:
    BASE58_AVAILABLE = False

class AxiomTradeClient:
    """
    Main client for interacting with Axiom Trade API with automatic token management
    """
    
    def __init__(self, username: str = None, password: str = None, 
                 auth_token: str = None, refresh_token: str = None,
                 storage_dir: str = None, use_saved_tokens: bool = True,
                 proxy: str = None):
        """
        Initialize AxiomTradeClient with enhanced authentication
        
        Args:
            username: Email for automatic login
            password: Password for automatic login  
            auth_token: Existing auth token (optional)
            refresh_token: Existing refresh token (optional)
            storage_dir: Directory for secure token storage
            use_saved_tokens: Whether to load/save tokens automatically (default: True)
            proxy: Proxy URL (socks5://user:pass@host:port or http://host:port)
        """
        # Initialize the enhanced auth manager
        self.auth_manager = AuthManager(
            username=username,
            password=password,
            auth_token=auth_token,
            refresh_token=refresh_token,
            storage_dir=storage_dir,
            use_saved_tokens=use_saved_tokens,
            proxy=proxy
        )
        
        # Initialize endpoints for trading functionality
        self.endpoints = Endpoints()
        
        # Initialize WebSocket client
        self.ws = AxiomTradeWebSocketClient(self.auth_manager)
        
        # Keep backward compatibility
        self.auth = self.auth_manager  # For legacy code
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        
        self.base_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Origin': 'https://axiom.trade',
            'Connection': 'keep-alive',
            'Referer': 'https://axiom.trade/',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site'
        }
    
    @property
    def access_token(self) -> Optional[str]:
        """Get current access token"""
        return self.auth_manager.tokens.access_token if self.auth_manager.tokens else None
    
    @property
    def refresh_token(self) -> Optional[str]:
        """Get current refresh token"""
        return self.auth_manager.tokens.refresh_token if self.auth_manager.tokens else None
    
    def login(self, email: str = None, password: str = None) -> Dict:
        """
        Login with username and password using the enhanced auth flow
        
        Args:
            email: Email address (optional if provided in constructor)
            password: Password (optional if provided in constructor)
            
        Returns:
            Dict: Login result with token information
        """
        # Use provided credentials or fall back to constructor values
        email = email or self.auth_manager.username
        password = password or self.auth_manager.password
        
        if not email or not password:
            raise ValueError("Email and password are required for login")
        
        # Update auth manager credentials
        self.auth_manager.username = email
        self.auth_manager.password = password
        
        # Perform authentication
        success = self.auth_manager.authenticate()
        
        if success and self.auth_manager.tokens:
            return {
                'success': True,
                'access_token': self.auth_manager.tokens.access_token,
                'refresh_token': self.auth_manager.tokens.refresh_token,
                'expires_at': self.auth_manager.tokens.expires_at,
                'message': 'Login successful'
            }
        else:
            return {
                'success': False,
                'message': 'Login failed'
            }
        
        return login_result
    
    def set_tokens(self, access_token: str, refresh_token: str) -> None:
        """
        Set authentication tokens directly
        
        Args:
            access_token: The access token
            refresh_token: The refresh token
        """
        self.auth_manager._set_tokens(access_token, refresh_token)
    
    def get_tokens(self) -> Dict[str, Optional[str]]:
        """
        Get current tokens
        """
        tokens = self.auth_manager.tokens
        return {
            'access_token': tokens.access_token if tokens else None,
            'refresh_token': tokens.refresh_token if tokens else None,
            'expires_at': tokens.expires_at if tokens else None,
            'is_expired': tokens.is_expired if tokens else True
        }
    
    def is_authenticated(self) -> bool:
        """
        Check if the client has valid authentication tokens
        """
        return self.auth_manager.is_authenticated()
    
    def refresh_access_token(self) -> bool:
        """
        Refresh the access token using stored refresh token
        
        Returns:
            bool: True if refresh was successful, False otherwise
        """
        return self.auth_manager.refresh_tokens()
    
    def ensure_authenticated(self) -> bool:
        """
        Ensure the client has valid authentication tokens
        Automatically refreshes or re-authenticates as needed
        
        Returns:
            bool: True if valid authentication available, False otherwise
        """
        return self.auth_manager.ensure_valid_authentication()
    
    def logout(self) -> None:
        """Clear all authentication data including saved tokens"""
        self.auth_manager.logout()
    
    def clear_saved_tokens(self) -> bool:
        """Clear saved tokens from secure storage"""
        return self.auth_manager.clear_saved_tokens()
    
    def has_saved_tokens(self) -> bool:
        """Check if saved tokens exist in secure storage"""
        return self.auth_manager.has_saved_tokens()
    
    def get_token_info_detailed(self) -> Dict:
        """Get detailed information about current tokens"""
        return self.auth_manager.get_token_info()
    
    def get_trending_tokens(self, time_period: str = '1h') -> Dict:
        """
        Get trending meme tokens
        Available time periods: 1h, 24h, 7d
        """
        # Ensure we have valid authentication
        if not self.ensure_authenticated():
            raise ValueError("Authentication failed. Please login first.")
        
        url = f'https://api6.axiom.trade/meme-trending?timePeriod={time_period}'
        
        try:
            response = self.auth_manager.make_authenticated_request('GET', url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            raise Exception(f"Failed to get trending tokens: {e}")
    
    def get_token_info(self, token_address: str) -> Dict:
        """
        Get information about a specific token
        """
        # Ensure we have valid authentication
        if not self.ensure_authenticated():
            raise ValueError("Authentication failed. Please login first.")
        
        # This endpoint might need to be confirmed with actual API documentation
        url = f'https://api6.axiom.trade/token/{token_address}'
        
        try:
            response = self.auth_manager.make_authenticated_request('GET', url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            raise Exception(f"Failed to get token info: {e}")
    
    def get_user_portfolio(self) -> Dict:
        """
        Get user's portfolio information
        """
        # Ensure we have valid authentication
        if not self.ensure_authenticated():
            raise ValueError("Authentication failed. Please login first.")
        
        url = 'https://api6.axiom.trade/portfolio'
        
        try:
            response = self.auth_manager.make_authenticated_request('GET', url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            raise Exception(f"Failed to get portfolio: {e}")
    
    def get_token_info_by_pair(self, pair_address: str) -> Dict:
        """
        Get token information by pair address
        
        Args:
            pair_address (str): The pair address to get info for
            
        Returns:
            Dict: Token information
        """
        # Ensure we have valid authentication
        if not self.ensure_authenticated():
            raise ValueError("Authentication failed. Please login first.")
        
        url = f'https://api10.axiom.trade/token-info?pairAddress={pair_address}'
        
        try:
            response = self.auth_manager.make_authenticated_request('GET', url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            raise Exception(f"Failed to get token info: {e}")
    
    def get_last_transaction(self, pair_address: str) -> Dict:
        """
        Get last transaction for a pair
        
        Args:
            pair_address (str): The pair address to get last transaction for
            
        Returns:
            Dict: Last transaction information
        """
        # Ensure we have valid authentication
        if not self.ensure_authenticated():
            raise ValueError("Authentication failed. Please login first.")
        
        url = f'https://api10.axiom.trade/last-transaction?pairAddress={pair_address}'
        
        try:
            response = self.auth_manager.make_authenticated_request('GET', url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            raise Exception(f"Failed to get last transaction: {e}")
    
    def get_pair_info(self, pair_address: str) -> Dict:
        """
        Get pair information
        
        Args:
            pair_address (str): The pair address to get info for
            
        Returns:
            Dict: Pair information
        """
        # Ensure we have valid authentication
        if not self.ensure_authenticated():
            raise ValueError("Authentication failed. Please login first.")
        
        url = f'https://api10.axiom.trade/pair-info?pairAddress={pair_address}'
        
        try:
            response = self.auth_manager.make_authenticated_request('GET', url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            raise Exception(f"Failed to get pair info: {e}")
    
    def get_pair_stats(self, pair_address: str) -> Dict:
        """
        Get pair statistics
        
        Args:
            pair_address (str): The pair address to get stats for
            
        Returns:
            Dict: Pair statistics
        """
        # Ensure we have valid authentication
        if not self.ensure_authenticated():
            raise ValueError("Authentication failed. Please login first.")
        
        url = f'https://api10.axiom.trade/pair-stats?pairAddress={pair_address}'
        
        try:
            response = self.auth_manager.make_authenticated_request('GET', url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            raise Exception(f"Failed to get pair stats: {e}")

    async def subscribe_new_tokens(self, callback):
        """
        Subscribe to new token updates via WebSocket
        
        Args:
            callback: Function to call when new token data is received
        """
        await self.ws.subscribe_new_tokens(callback)
    
    def get_meme_open_positions(self, wallet_address: str) -> Dict:
        """
        Get open meme token positions for a wallet
        
        Args:
            wallet_address (str): The wallet address to get positions for
            
        Returns:
            Dict: Open positions information
        """
        # Ensure we have valid authentication
        if not self.ensure_authenticated():
            raise ValueError("Authentication failed. Please login first.")
        
        url = f'https://api10.axiom.trade/meme-open-positions?walletAddress={wallet_address}'
        
        try:
            response = self.auth_manager.make_authenticated_request('GET', url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            raise Exception(f"Failed to get open positions: {e}")
    
    def get_holder_data(self, pair_address: str, only_tracked_wallets: bool = False) -> Dict:
        """
        Get holder data for a pair
        
        Args:
            pair_address (str): The pair address to get holder data for
            only_tracked_wallets (bool): Whether to only include tracked wallets
            
        Returns:
            Dict: Holder data information
        """
        # Ensure we have valid authentication
        if not self.ensure_authenticated():
            raise ValueError("Authentication failed. Please login first.")
        
        url = f'https://api10.axiom.trade/holder-data-v3?pairAddress={pair_address}&onlyTrackedWallets={str(only_tracked_wallets).lower()}'
        
        try:
            response = self.auth_manager.make_authenticated_request('GET', url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            raise Exception(f"Failed to get holder data: {e}")
    
    def get_dev_tokens(self, dev_address: str) -> Dict:
        """
        Get tokens created by a developer address
        
        Args:
            dev_address (str): The developer address to get tokens for
            
        Returns:
            Dict: Developer tokens information
        """
        # Ensure we have valid authentication
        if not self.ensure_authenticated():
            raise ValueError("Authentication failed. Please login first.")
        
        url = f'https://api10.axiom.trade/dev-tokens-v2?devAddress={dev_address}'
        
        try:
            response = self.auth_manager.make_authenticated_request('GET', url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            raise Exception(f"Failed to get dev tokens: {e}")
    
    def get_token_analysis(self, dev_address: str, token_ticker: str) -> Dict:
        """
        Get token analysis for a developer and token ticker
        
        Args:
            dev_address (str): The developer address
            token_ticker (str): The token ticker to analyze
            
        Returns:
            Dict: Token analysis information
        """
        # Ensure we have valid authentication
        if not self.ensure_authenticated():
            raise ValueError("Authentication failed. Please login first.")
        
        url = f'https://api10.axiom.trade/token-analysis?devAddress={dev_address}&tokenTicker={token_ticker}'
        
        try:
            response = self.auth_manager.make_authenticated_request('GET', url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            raise Exception(f"Failed to get token analysis: {e}")

    def get_twitter_community_info(self, community_id: str) -> Dict:
        """
        Get Twitter community information
        
        Args:
            community_id (str): The Twitter community ID to get info for
            
        Returns:
            Dict: Community information including name, creator, members, etc.
        """
        # Ensure we have valid authentication
        if not self.ensure_authenticated():
            raise ValueError("Authentication failed. Please login first.")
        
        url = f'https://api.axiom.trade/twitter-community-info?communityId={community_id}'
        
        try:
            response = self.auth_manager.make_authenticated_request('GET', url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            raise Exception(f"Failed to get community info: {e}")
    
    def get_transactions_feed(self, pair_address: str, order_by: str = 'ASC', 
                              maker_address: str = '') -> List[Dict]:
        """
        Get transactions feed for a pair
        
        Args:
            pair_address (str): The pair address to get transactions for
            order_by (str): Order direction - 'ASC' or 'DESC' (default: 'ASC')
            maker_address (str): Optional maker address filter (default: '')
            
        Returns:
            List[Dict]: List of transactions
        """
        # Ensure we have valid authentication
        import time
        current_ts = int(time.time() * 1000)
        url = f'https://api.axiom.trade/transactions-feed-v2?pairAddress={pair_address}&orderBy={order_by}&makerAddress={maker_address}&v={current_ts}'
        
        try:
            response = self.auth_manager.make_authenticated_request('GET', url)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            raise Exception(f"Failed to get transactions feed: {e}")


    def get_pair_chart(self, pair_address: str, from_ts: int, to_ts: int, 
                       interval: str = "1s", count_bars: int = 300, 
                       pair_created_at: Optional[int] = None,
                       open_trading: Optional[int] = None,
                       last_transaction_time: Optional[int] = None,
                       currency: str = "SOL") -> List[Dict]:
        """
        Get pair chart candles (OHLCV).
        
        Args:
            pair_address (str): The pair address.
            from_ts (int): Start timestamp in milliseconds.
            to_ts (int): End timestamp in milliseconds.
            interval (str): Candle interval, default "1s".
            count_bars (int): Number of bars to return, default 300.
            pair_created_at (Optional[int]): Creation timestamp (optimization).
            open_trading (Optional[int]): Open trading timestamp (optimization).
            last_transaction_time (Optional[int]): Last transaction timestamp (optimization).
            currency (str): Currency for prices, "SOL" or "USD". Default "SOL".
            
        Returns:
            List[Dict]: List of candle data.
        """
        # Ensure we have valid authentication
        if not self.ensure_authenticated():
            raise ValueError("Authentication failed. Please login first.")

        # Construct query parameters
        import time
        current_ts = int(time.time() * 1000)
        
        params = {
            "pairAddress": pair_address,
            "from": from_ts,
            "to": to_ts,
            "currency": currency,
            "interval": interval,
            "countBars": count_bars,
            "showOutliers": "false",
            "isNew": "false",
            "v": current_ts  # Use current timestamp instead of static "2"
        }
        
        if pair_created_at:
            params["pairCreatedAt"] = pair_created_at
        if open_trading:
            params["openTrading"] = open_trading
        if last_transaction_time:
            params["lastTransactionTime"] = last_transaction_time
            
        # Manually constructing the URL to ensure correct parameter encoding if needed, 
        # or just pass params to requests. 
        # Use pair-chart-v2 endpoint
        url = "https://api8.axiom.trade/pair-chart-v2"
        
        # Build full URL for debugging
        from urllib.parse import urlencode
        full_url = f"{url}?{urlencode(params)}"
        
        try:
            response = self.auth_manager.make_authenticated_request('GET', url, params=params)
            response.raise_for_status()
            data = response.json()
            
            # Helper to convert array format to dict format
            def convert_candle(c):
                if isinstance(c, dict):
                    return c
                elif isinstance(c, list) and len(c) >= 6:
                    # v2 format: [time, open, high, low, close, volume]
                    return {
                        "time": c[0],
                        "open": c[1],
                        "high": c[2],
                        "low": c[3],
                        "close": c[4],
                        "volume": c[5] if len(c) > 5 else 0
                    }
                return None
            
            candles = []
            if isinstance(data, list):
                for item in data:
                    converted = convert_candle(item)
                    if converted:
                        candles.append(converted)
                if not candles and data:
                    self.logger.warning(f"⚠️ Could not parse candles. First item: {data[0] if data else 'empty'}. URL: {full_url}")
                return candles
            elif isinstance(data, dict):
                # Try to find the list in common keys
                for key in ["data", "candles", "bars", "result", "items"]:
                    if key in data and isinstance(data[key], list):
                        raw_list = data[key]
                        for item in raw_list:
                            converted = convert_candle(item)
                            if converted:
                                candles.append(converted)
                        return candles
                
                # If no list found, maybe the dict IS the candle (unlikely) or it's an error/empty
                self.logger.warning(f"get_pair_chart returned dict with keys: {list(data.keys())}. URL: {full_url}")
                return []
            else:
                self.logger.warning(f"get_pair_chart returned unexpected type: {type(data)}. URL: {full_url}")
                return []
                
        except Exception as e:
            self.logger.error(f"Failed to get pair chart. URL: {full_url}")
            raise Exception(f"Failed to get pair chart: {e}")

    def analyze_pair_ath_intervals(self, pair_address: str, currency: str = "SOL") -> Dict[str, Dict[str, float]]:
        """
        Analyze ATH after 1, 2, 5, 10 minutes from creation (or open trading).
        
        Args:
            pair_address (str): The pair address.
            currency (str): Currency to use ("SOL" or "USD"). Default: "SOL".
            
        Returns:
            Dict[str, Dict[str, float]]: Map of intervals to price/mcap data.
        """
        # 1. Get pair info to find creation time and open trading time
        try:
            pair_info = self.get_pair_info(pair_address)
            
            # Helper to parse timestamps
            def parse_ts(val):
                if not val: return None
                if isinstance(val, int) or (isinstance(val, str) and val.isdigit()):
                    return int(val)
                try:
                    import datetime
                    val_str = str(val).replace('Z', '+00:00')
                    dt = datetime.datetime.fromisoformat(val_str)
                    return int(dt.timestamp() * 1000)
                except:
                    return None

            created_at = pair_info.get("createdAt") or pair_info.get("pairCreatedAt")
            if not created_at and "pair" in pair_info: 
                 created_at = pair_info["pair"].get("createdAt")
            
            open_trading = pair_info.get("openTrading") or pair_info.get("pair", {}).get("openTrading")
            supply = float(pair_info.get("supply", 0))
            
            # Check if pair was migrated (e.g., from Pump to Raydium)
            # If so, use the migrated pair address for candle fetching
            chart_pair_address = pair_address
            extra = pair_info.get("extra", {})
            
            # Check multiple possible locations for migrated address
            migrated_to = None
            if extra and extra.get("migratedTo"):
                migrated_to = extra["migratedTo"]
            elif pair_info.get("migratedTo"):
                migrated_to = pair_info["migratedTo"]
            elif pair_info.get("pair", {}).get("migratedTo"):
                migrated_to = pair_info["pair"]["migratedTo"]
            elif extra and extra.get("migratedPair"):
                migrated_to = extra["migratedPair"]
            elif pair_info.get("migratedPair"):
                migrated_to = pair_info["migratedPair"]
            
            if migrated_to:
                self.logger.info(f"Pair {pair_address} migrated to {migrated_to}, using migrated address for candles")
                chart_pair_address = migrated_to
            else:
                # Debug: Log available keys to find migration info
                self.logger.warning(f"🔍 No migration found for {pair_address}. Keys: {list(pair_info.keys())}, extra: {list(extra.keys()) if extra else 'None'}")
            
            created_at_ms = parse_ts(created_at)
            open_trading_ms = parse_ts(open_trading)
            
            # Determine start time: prefer open_trading, fallback to created_at
            if open_trading_ms:
                start_ts = open_trading_ms
            elif created_at_ms:
                start_ts = created_at_ms
            else:
                raise ValueError("Could not determine start time (no creation or openTrading time)")
                
        except Exception as e:
             raise Exception(f"Error fetching pair info for analysis: {e}")


        # Define intervals in milliseconds (for reference, logic uses raw minutes)
        intervals_map = {
            "1min": 1,
            "3min": 3, 
            "5min": 5,
            "10min": 10,
            "30min": 30,
            "60min": 60,
            "240min": 240
        }
        # Updated to match DB schema: 1, 3, 5, 10, 30, 60, 240
        output_intervals = [1, 3, 5, 10, 30, 60, 240]
        
        # 2. Use current time as lastTransactionTime (saves API call, works fine)
        import time
        last_transaction_time = int(time.time() * 1000)

        needed_duration_minutes = 245 # Small buffer over 240
        end_ts = start_ts + (needed_duration_minutes * 60 * 1000)
        
        try:
            candles = self.get_pair_chart(
                pair_address=chart_pair_address,
                from_ts=start_ts,
                to_ts=end_ts,
                interval="1m",
                count_bars=300, 
                pair_created_at=created_at_ms,
                open_trading=open_trading_ms,
                last_transaction_time=last_transaction_time,
                currency=currency
            )
        except Exception as e:
            self.logger.error(f"Error fetching candles for {chart_pair_address}: {e}")
            candles = []


        # 3. Calculate ATH for each interval
        results = {}
        
        if not candles:
            # DEBUG: Log why we have no candles
            self.logger.warning(
                f"⚠️ Empty candles for {pair_address}: "
                f"chart_addr={chart_pair_address}, "
                f"created_at={created_at_ms}, "
                f"open_trading={open_trading_ms}, "
                f"start_ts={start_ts}, "
                f"end_ts={end_ts}, "
                f"last_tx={last_transaction_time}"
            )
            return {f"{k}min": {"price": 0.0, "mcap": 0.0} for k in output_intervals}
        
        # print(f"[DEBUG LIB] Candles count: {len(candles)}")
        # if candles:
        #     print(f"[DEBUG LIB] First candle: {candles[0]}")
        # candles.sort(key=lambda x: x.get("time", 0))
        
        # Helper to get max high from first N candles
        def get_max_high(n_candles):
            if not candles:
                return 0.0
            subset = candles[:n_candles]
            if not subset:
                return 0.0
            return max(float(c.get("high", 0)) for c in subset)

        for mins in output_intervals:
            ath_price = get_max_high(mins)
            results[f"{mins}min"] = {
                "price": ath_price,
                "mcap": ath_price * supply
            }
                
        return results

    def analyze_pair_ath_1s(self, pair_address: str, currency: str = "SOL") -> Dict[str, Dict[str, float]]:
        """
        Analyze ATH after 1 second from creation (or open trading).
        
        Args:
            pair_address (str): The pair address.
            currency (str): Currency to use ("SOL" or "USD"). Default: "SOL".
            
        Returns:
            Dict[str, Dict[str, float]]: Map of intervals to price/mcap data.
        """
        # 1. Get pair info to find creation time and open trading time
        try:
            pair_info = self.get_pair_info(pair_address)
            
            # Helper to parse timestamps
            def parse_ts(val):
                if not val: return None
                if isinstance(val, int) or (isinstance(val, str) and val.isdigit()):
                    return int(val)
                try:
                    import datetime
                    val_str = str(val).replace('Z', '+00:00')
                    dt = datetime.datetime.fromisoformat(val_str)
                    return int(dt.timestamp() * 1000)
                except:
                    return None

            created_at = pair_info.get("createdAt") or pair_info.get("pairCreatedAt")
            if not created_at and "pair" in pair_info: 
                 created_at = pair_info["pair"].get("createdAt")
            
            open_trading = pair_info.get("openTrading") or pair_info.get("pair", {}).get("openTrading")
            supply = float(pair_info.get("supply", 0))
            
            created_at_ms = parse_ts(created_at)
            open_trading_ms = parse_ts(open_trading)
            
            # Determine start time: prefer open_trading, fallback to created_at
            if open_trading_ms:
                start_ts = open_trading_ms
            elif created_at_ms:
                start_ts = created_at_ms
            else:
                raise ValueError("Could not determine start time (no creation or openTrading time)")
                
        except Exception as e:
             raise Exception(f"Error fetching pair info for analysis: {e}")

        # 2. Get last transaction time (Required by API)
        last_transaction_time = None
        try:
            last_tx = self.get_last_transaction(pair_address)
            if last_tx and "createdAt" in last_tx:
                import datetime
                lt_str = last_tx["createdAt"].replace('Z', '+00:00')
                dt = datetime.datetime.fromisoformat(lt_str)
                last_transaction_time = int(dt.timestamp() * 1000)
        except Exception as e:
            self.logger.warning(f"Error fetching last transaction: {e}")

        # We need very short duration for 1s check, but let's fetch a bit more to be safe
        needed_duration_seconds = 10 
        end_ts = start_ts + (needed_duration_seconds * 1000)
        
        try:
            # Fetch 1s candles
            candles = self.get_pair_chart(
                pair_address=pair_address,
                from_ts=start_ts,
                to_ts=end_ts,
                interval="1s", # Requesting 1s interval
                count_bars=300, 
                pair_created_at=created_at_ms,
                open_trading=open_trading_ms,
                last_transaction_time=last_transaction_time,
                currency=currency
            )
        except Exception as e:
            self.logger.error(f"Error fetching candles for {pair_address}: {e}")
            candles = []

        # 3. Calculate ATH for 1s interval
        results = {}
        
        if not candles:
             return {"1s": {"price": 0.0, "mcap": 0.0}}
        
        # Sort candles by time
        candles.sort(key=lambda x: x.get("time", 0))
        
        # Helper to get max high from first N seconds (candles are 1s)
        def get_max_high_seconds(n_seconds):
            if not candles:
                return 0.0
            
            # Filter candles that are within the first n_seconds from start_ts
            # Note: get_pair_chart returns candles with 'time' (start of candle)
            
            cutoff = start_ts + (n_seconds * 1000)
            subset = [c for c in candles if c.get("time", 0) < cutoff]
            
            if not subset:
                 # If no candles strictly < cutoff (maybe first candle starts AT start_ts), take the first one if it's close?
                 # Actually, usually candle at start_ts covers [start_ts, start_ts+1s).
                 # So for 1s check, we want candles where time < start_ts + 1000.
                 return 0.0
                 
            return max(float(c.get("high", 0)) for c in subset)

        ath_price = get_max_high_seconds(1)
        # Fallback: if 0, maybe take the first candle's high/close? 
        # Sometimes 1st candle might be slightly delayed or aligned. 
        # If strict 1s yields nothing, let's try to grab *at least* the first available candle if it's very close.
        if ath_price == 0.0 and candles:
            first_candle = candles[0]
            if first_candle.get("time", 0) <= start_ts + 1000:
                 ath_price = float(first_candle.get("high", 0))

        results["1s"] = {
            "price": ath_price,
            "mcap": ath_price * supply
        }
                
        return results
    
    def send_transaction_to_rpc(self, signed_transaction_base64: str, 
                               rpc_url: str = "https://greer-651y13-fast-mainnet.helius-rpc.com/") -> Dict[str, Union[str, bool]]:
        """
        Send a base64 encoded signed transaction directly to Solana RPC endpoint.
        (Legacy method for backward compatibility)
        
        Args:
            signed_transaction_base64 (str): Base64 encoded signed transaction
            rpc_url (str): Solana RPC endpoint URL
            
        Returns:
            Dict with transaction signature and success status
        """
        try:
            headers = {
                'accept': 'application/json, text/plain, */*',
                'accept-language': 'en-US,en;q=0.9,es;q=0.8,fr;q=0.7,de;q=0.6,ru;q=0.5',
                'content-type': 'application/json',
                'origin': 'https://axiom.trade',
                'priority': 'u=1, i',
                'referer': 'https://axiom.trade/',
                'sec-ch-ua': '"Opera GX";v="120", "Not-A.Brand";v="8", "Chromium";v="135"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'cross-site',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 OPR/120.0.0.0'
            }
            
            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "sendTransaction",
                "params": [
                    signed_transaction_base64,
                    {
                        "encoding": "base64",
                        "skipPreflight": True,
                        "preflightCommitment": "confirmed",
                        "maxRetries": 0
                    }
                ]
            }
            
            self.logger.info(f"Sending base64 transaction to RPC: {rpc_url}")
            
            response = requests.post(rpc_url, headers=headers, json=payload, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                if "result" in result:
                    signature = result["result"]
                    self.logger.info(f"Transaction sent successfully. Signature: {signature}")
                    return {
                        "success": True,
                        "signature": signature,
                        "transactionId": signature,
                        "explorer_url": f"https://solscan.io/tx/{signature}"
                    }
                elif "error" in result:
                    error_msg = f"RPC Error: {result['error']}"
                    self.logger.error(error_msg)
                    return {"success": False, "error": error_msg}
                else:
                    error_msg = f"Unexpected RPC response: {result}"
                    self.logger.error(error_msg)
                    return {"success": False, "error": error_msg}
            else:
                error_msg = f"Failed to send transaction: {response.status_code} - {response.text}"
                self.logger.error(error_msg)
                return {"success": False, "error": error_msg}
                
        except Exception as e:
            error_msg = f"Error sending transaction to RPC: {str(e)}"
            self.logger.error(error_msg)
            return {"success": False, "error": error_msg}

    # ==================== TRADING METHODS ====================
    
    def buy_token(self, private_key: str, token_mint: str, amount: float, 
                  slippage_percent: float = 10, priority_fee: float = 0.005, 
                  pool: str = "auto", denominated_in_sol: bool = True,
                  rpc_url: str = "https://api.mainnet-beta.solana.com/") -> Dict[str, Union[str, bool]]:
        """
        Buy a token using SOL via PumpPortal API following their exact specification.
        
        Args:
            private_key (str): Private key as base58 string
            token_mint (str): Token mint address to buy
            amount (float): Amount of SOL or tokens to trade
            slippage_percent (float): Slippage tolerance percentage (default: 10%)
            priority_fee (float): Priority fee in SOL (default: 0.005)
            pool (str): Exchange to trade on - "pump", "raydium", "pump-amm", 
                       "launchlab", "raydium-cpmm", "bonk", or "auto" (default: "auto")
            denominated_in_sol (bool): True if amount is SOL, False if amount is tokens (default: True)
            rpc_url (str): Solana RPC endpoint URL
            
        Returns:
            Dict with transaction signature and success status
        """
        if not SOLDERS_AVAILABLE:
            return {
                "success": False, 
                "error": "solders library not installed. Run: pip install solders"
            }
        
        try:
            from solders.keypair import Keypair
            from solders.transaction import VersionedTransaction
            from solders.commitment_config import CommitmentLevel
            from solders.rpc.requests import SendVersionedTransaction
            from solders.rpc.config import RpcSendTransactionConfig
            
            # Convert private key to Keypair - use Keypair.from_base58_string as per PumpPortal example
            keypair = Keypair.from_base58_string(private_key)
            public_key = str(keypair.pubkey())
            
            self.logger.info(
                "\n"
                "================= BUY ORDER =================\n"
                f"  Action:            BUY\n"
                f"  Token Mint:        {token_mint}\n"
                f"  Amount:            {amount} {'SOL' if denominated_in_sol else 'tokens'}\n"
                f"  Slippage:          {int(slippage_percent)}%\n"
                f"  Priority Fee:      {priority_fee} SOL\n"
                f"  Pool:              {pool}\n"
                f"  Buyer Public Key:  {public_key}\n"
                "============================================="
            )
            
            # Prepare trade data exactly as PumpPortal expects
            # According to PumpPortal docs (https://pumpportal.fun/local-trading-api/trading-api): amount should be in SOL or tokens.
            trade_data = {
                "publicKey": public_key,
                "action": "buy",
                "mint": token_mint,
                "amount": amount,
                "denominatedInSol": "true" if denominated_in_sol else "false",
                "slippage": int(slippage_percent),
                "priorityFee": priority_fee,
                "pool": pool
            }
            
            self.logger.info(f"Sending trade request to PumpPortal with data: {trade_data}")
            
            # Get transaction from PumpPortal exactly as shown in their example
            response = requests.post(url="https://pumpportal.fun/api/trade-local", data=trade_data)
            
            if response.status_code != 200:
                error_msg = f"PumpPortal API error: {response.status_code} - {response.text}"
                self.logger.error(error_msg)
                return {"success": False, "error": error_msg}
            
            # Create transaction exactly as PumpPortal shows
            tx = VersionedTransaction(VersionedTransaction.from_bytes(response.content).message, [keypair])
            
            # Configure and send transaction exactly as PumpPortal example
            commitment = CommitmentLevel.Confirmed
            config = RpcSendTransactionConfig(preflight_commitment=commitment)
            txPayload = SendVersionedTransaction(tx, config)
            
            # Send to RPC endpoint exactly as PumpPortal example
            response = requests.post(
                url=rpc_url,
                headers={"Content-Type": "application/json"},
                data=txPayload.to_json()
            )
            
            if response.status_code == 200:
                result = response.json()
                if "result" in result:
                    tx_signature = result['result']
                    self.logger.info(f"Transaction successful. Signature: {tx_signature}")
                    return {
                        "success": True,
                        "signature": tx_signature,
                        "transactionId": tx_signature,
                        "explorer_url": f"https://solscan.io/tx/{tx_signature}"
                    }
                elif "error" in result:
                    error_msg = f"RPC Error: {result['error']}"
                    self.logger.error(error_msg)
                    return {"success": False, "error": error_msg}
                else:
                    error_msg = f"Unexpected RPC response: {result}"
                    self.logger.error(error_msg)
                    return {"success": False, "error": error_msg}
            else:
                error_msg = f"Failed to send transaction: {response.status_code} - {response.text}"
                self.logger.error(error_msg)
                return {"success": False, "error": error_msg}
            
        except Exception as e:
            error_msg = f"Error in buy_token: {str(e)}"
            self.logger.error(error_msg)
            return {"success": False, "error": error_msg}
    
    def sell_token(self, private_key: str, token_mint: str, amount: Union[float, str], 
                   slippage_percent: float = 10, priority_fee: float = 0.005, 
                   pool: str = "auto", denominated_in_sol: bool = False,
                   rpc_url: str = "https://api.mainnet-beta.solana.com/") -> Dict[str, Union[str, bool]]:
        """
        Sell a token for SOL via PumpPortal API following their exact specification.
        
        Args:
            private_key (str): Private key as base58 string
            token_mint (str): Token mint address to sell
            amount (Union[float, str]): Amount of tokens or SOL to trade. Can be:
                                      - float: Exact number of tokens/SOL
                                      - str: Percentage like "100%" to sell all owned tokens
            slippage_percent (float): Slippage tolerance percentage (default: 10%)
            priority_fee (float): Priority fee in SOL (default: 0.005)
            pool (str): Exchange to trade on - "pump", "raydium", "pump-amm", 
                       "launchlab", "raydium-cpmm", "bonk", or "auto" (default: "auto")
            denominated_in_sol (bool): True if amount is SOL, False if amount is tokens (default: False)
            rpc_url (str): Solana RPC endpoint URL
            
        Returns:
            Dict with transaction signature and success status
        """
        if not SOLDERS_AVAILABLE:
            return {
                "success": False, 
                "error": "solders library not installed. Run: pip install solders"
            }
        
        try:
            from solders.keypair import Keypair
            from solders.transaction import VersionedTransaction
            from solders.commitment_config import CommitmentLevel
            from solders.rpc.requests import SendVersionedTransaction
            from solders.rpc.config import RpcSendTransactionConfig
            
            # Convert private key to Keypair - use Keypair.from_base58_string as per PumpPortal example
            keypair = Keypair.from_base58_string(private_key)
            public_key = str(keypair.pubkey())
            
            # Handle amount parameter - can be float or percentage string like "100%"
            amount_str_or_float = str(amount) if isinstance(amount, str) else amount
            
            self.logger.info(
                "\n"
                "================= SELL ORDER =================\n"
                f"  Action:            SELL\n"
                f"  Token Mint:        {token_mint}\n"
                f"  Amount:            {amount_str_or_float} {'SOL' if denominated_in_sol else 'tokens'}\n"
                f"  Slippage:          {int(slippage_percent)}%\n"
                f"  Priority Fee:      {priority_fee} SOL\n"
                f"  Pool:              {pool}\n"
                f"  Seller Public Key: {public_key}\n"
                "============================================="
            )
            
            # Prepare trade data exactly as PumpPortal expects
            # According to PumpPortal docs: amount can be number or percentage string like "100%"
            trade_data = {
                "publicKey": public_key,
                "action": "sell",
                "mint": token_mint,
                "amount": amount_str_or_float,  # Send amount as-is - can be number or percentage string
                "denominatedInSol": "true" if denominated_in_sol else "false",
                "slippage": int(slippage_percent),
                "priorityFee": priority_fee,
                "pool": pool
            }
            
            self.logger.info(f"Sending trade request to PumpPortal with data: {trade_data}")
            
            # Get transaction from PumpPortal exactly as shown in their example
            response = requests.post(url="https://pumpportal.fun/api/trade-local", data=trade_data)
            
            if response.status_code != 200:
                error_msg = f"PumpPortal API error: {response.status_code} - {response.text}"
                self.logger.error(error_msg)
                return {"success": False, "error": error_msg}
            
            # Create transaction exactly as PumpPortal shows
            tx = VersionedTransaction(VersionedTransaction.from_bytes(response.content).message, [keypair])
            
            # Configure and send transaction exactly as PumpPortal example
            commitment = CommitmentLevel.Confirmed
            config = RpcSendTransactionConfig(preflight_commitment=commitment)
            txPayload = SendVersionedTransaction(tx, config)
            
            # Send to RPC endpoint exactly as PumpPortal example
            response = requests.post(
                url=rpc_url,
                headers={"Content-Type": "application/json"},
                data=txPayload.to_json()
            )
            
            if response.status_code == 200:
                result = response.json()
                if "result" in result:
                    tx_signature = result['result']
                    self.logger.info(f"Transaction successful. Signature: {tx_signature}")
                    return {
                        "success": True,
                        "signature": tx_signature,
                        "transactionId": tx_signature,
                        "explorer_url": f"https://solscan.io/tx/{tx_signature}"
                    }
                elif "error" in result:
                    error_msg = f"RPC Error: {result['error']}"
                    self.logger.error(error_msg)
                    return {"success": False, "error": error_msg}
                else:
                    error_msg = f"Unexpected RPC response: {result}"
                    self.logger.error(error_msg)
                    return {"success": False, "error": error_msg}
            else:
                error_msg = f"Failed to send transaction: {response.status_code} - {response.text}"
                self.logger.error(error_msg)
                return {"success": False, "error": error_msg}
            
        except Exception as e:
            error_msg = f"Error in sell_token: {str(e)}"
            self.logger.error(error_msg)
            return {"success": False, "error": error_msg}
    
    def get_token_balance(self, wallet_address: str, token_mint: str) -> Optional[float]:
        """
        Get the balance of a specific token for a wallet.
        
        Args:
            wallet_address (str): Wallet public key
            token_mint (str): Token mint address
            
        Returns:
            Token balance as float, or None if error
        """
        try:
            # Ensure we have valid authentication
            if not self.ensure_authenticated():
                raise ValueError("Authentication failed")
            
            payload = {
                "publicKey": wallet_address,
                "tokenMint": token_mint
            }
            
            url = f"{self.endpoints.BASE_URL_API}{self.endpoints.ENDPOINT_GET_TOKEN_BALANCE}"
            response = self.auth_manager.make_authenticated_request('POST', url, json=payload)
            
            if response.status_code == 200:
                result = response.json()
                balance = result.get("balance", 0)
                self.logger.info(f"Token balance for {token_mint}: {balance}")
                return float(balance)
            else:
                self.logger.error(f"Failed to get token balance: {response.status_code}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error getting token balance: {str(e)}")
            return None
    
    def get_sol_balance(self, wallet_address: str) -> Optional[float]:
        """
        Get SOL balance for a wallet address.
        
        Args:
            wallet_address (str): Wallet public key
            
        Returns:
            SOL balance as float, or None if error
        """
        try:
            # Ensure we have valid authentication
            if not self.ensure_authenticated():
                raise ValueError("Authentication failed")
            
            payload = {"publicKey": wallet_address}
            
            url = f"{self.endpoints.BASE_URL_API}{self.endpoints.ENDPOINT_GET_BALANCE}"
            response = self.auth_manager.make_authenticated_request('POST', url, json=payload)
            
            if response.status_code == 200:
                result = response.json()
                balance = result.get("balance", 0)
                self.logger.info(f"SOL balance for {wallet_address}: {balance}")
                return float(balance)
            else:
                self.logger.error(f"Failed to get SOL balance: {response.status_code}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error getting SOL balance: {str(e)}")
            return None
    
    def _send_transaction_to_rpc(self, signed_transaction, 
                                rpc_url: str = "https://greer-651y13-fast-mainnet.helius-rpc.com/") -> Dict[str, Union[str, bool]]:
        """
        Send a signed VersionedTransaction to Solana RPC endpoint.
        
        Args:
            signed_transaction: VersionedTransaction object that's already signed
            rpc_url (str): Solana RPC endpoint URL
            
        Returns:
            Dict with transaction signature and success status
        """
        try:
            from solders.commitment_config import CommitmentLevel
            from solders.rpc.requests import SendVersionedTransaction
            from solders.rpc.config import RpcSendTransactionConfig
            
            # Configure transaction sending
            commitment = CommitmentLevel.Confirmed
            config = RpcSendTransactionConfig(preflight_commitment=commitment)
            tx_payload = SendVersionedTransaction(signed_transaction, config)
            
            headers = {
                'accept': 'application/json, text/plain, */*',
                'accept-language': 'en-US,en;q=0.9,es;q=0.8,fr;q=0.7,de;q=0.6,ru;q=0.5',
                'content-type': 'application/json',
                'origin': 'https://axiom.trade',
                'priority': 'u=1, i',
                'referer': 'https://axiom.trade/',
                'sec-ch-ua': '"Opera GX";v="120", "Not-A.Brand";v="8", "Chromium";v="135"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'cross-site',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 OPR/120.0.0.0'
            }
            
            self.logger.info(f"Sending transaction to RPC: {rpc_url}")
            
            response = requests.post(
                url=rpc_url,
                headers=headers,
                data=tx_payload.to_json(),
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                if "result" in result:
                    signature = result["result"]
                    self.logger.info(f"Transaction sent successfully. Signature: {signature}")
                    return {
                        "success": True,
                        "signature": signature,
                        "transactionId": signature,
                        "explorer_url": f"https://solscan.io/tx/{signature}"
                    }
                elif "error" in result:
                    error_msg = f"RPC Error: {result['error']}"
                    self.logger.error(error_msg)
                    return {"success": False, "error": error_msg}
                else:
                    error_msg = f"Unexpected RPC response: {result}"
                    self.logger.error(error_msg)
                    return {"success": False, "error": error_msg}
            else:
                error_msg = f"Failed to send transaction: {response.status_code} - {response.text}"
                self.logger.error(error_msg)
                return {"success": False, "error": error_msg}
                
        except Exception as e:
            error_msg = f"Error sending transaction to RPC: {str(e)}"
            self.logger.error(error_msg)
            return {"success": False, "error": error_msg}
    
    def _get_keypair_from_private_key(self, private_key: str) -> Keypair:
        """Convert private key string to Keypair object."""
        if not SOLDERS_AVAILABLE:
            raise ImportError("solders library not installed. Run: pip install solders")
        
        try:
            if isinstance(private_key, str):
                # Try to decode as base58 first
                try:
                    if BASE58_AVAILABLE:
                        import base58
                        private_key_bytes = base58.b58decode(private_key)
                    else:
                        # Fallback to assuming it's hex
                        private_key_bytes = bytes.fromhex(private_key)
                except:
                    # Try as hex string
                    try:
                        private_key_bytes = bytes.fromhex(private_key)
                    except:
                        # Try as base64
                        try:
                            private_key_bytes = base64.b64decode(private_key)
                        except:
                            raise ValueError("Unable to decode private key")
            else:
                private_key_bytes = private_key
            
            return Keypair.from_bytes(private_key_bytes)
        except Exception as e:
            raise ValueError(f"Invalid private key format: {e}")
    
    def _sign_and_send_transaction(self, keypair: Keypair, transaction_data: Dict) -> Dict[str, Union[str, bool]]:
        """Sign and send a transaction to the Solana network."""
        if not SOLDERS_AVAILABLE:
            return {
                "success": False, 
                "error": "solders library not installed. Run: pip install solders"
            }
        
        try:
            # Extract transaction from response
            if "transaction" in transaction_data:
                transaction_b64 = transaction_data["transaction"]
            elif "serializedTransaction" in transaction_data:
                transaction_b64 = transaction_data["serializedTransaction"]
            else:
                raise ValueError("No transaction found in API response")
            
            # Decode and deserialize transaction
            transaction_bytes = base64.b64decode(transaction_b64)
            transaction = Transaction.from_bytes(transaction_bytes)
            
            # Sign the transaction
            signed_transaction = transaction
            signed_transaction.sign([keypair])
            
            # Send the signed transaction back to API
            send_data = {
                "signedTransaction": base64.b64encode(bytes(signed_transaction)).decode('utf-8')
            }
            
            url = f"{self.endpoints.BASE_URL_API}{self.endpoints.ENDPOINT_SEND_TRANSACTION}"
            response = self.auth_manager.make_authenticated_request('POST', url, json=send_data)
            
            if response.status_code == 200:
                result = response.json()
                signature = result.get("signature", "")
                self.logger.info(f"Transaction sent successfully. Signature: {signature}")
                return {
                    "success": True,
                    "signature": signature,
                    "transactionId": signature
                }
            else:
                error_msg = f"Failed to send transaction: {response.status_code} - {response.text}"
                self.logger.error(error_msg)
                return {"success": False, "error": error_msg}
                
        except Exception as e:
            error_msg = f"Error signing/sending transaction: {str(e)}"
            self.logger.error(error_msg)
            return {"success": False, "error": error_msg}
    
    # Backward compatibility aliases for old _client.py API
    def GetBalance(self, wallet_address: str) -> Dict[str, Union[float, int]]:
        """
        Legacy method for backward compatibility. 
        Use get_sol_balance() for new code.
        """
        balance_sol = self.get_sol_balance(wallet_address)
        if balance_sol is not None:
            lamports = int(balance_sol * 1_000_000_000)
            return {
                "sol": balance_sol,
                "lamports": lamports,
                "slot": 0  # Not available from this method
            }
        return None

# Convenience functions for quick usage
def quick_login_and_get_trending(email: str, b64_password: str, otp_code: str, time_period: str = '1h') -> Dict:
    """
    Quick function to login and get trending tokens in one call
    """
    client = AxiomTradeClient()
    client.login(email, b64_password, otp_code)
    return client.get_trending_tokens(time_period)

def get_trending_with_token(access_token: str, time_period: str = '1h') -> Dict:
    """
    Quick function to get trending tokens with existing access token
    """
    client = AxiomTradeClient()
    client.set_tokens(access_token=access_token)
    return client.get_trending_tokens(time_period)
