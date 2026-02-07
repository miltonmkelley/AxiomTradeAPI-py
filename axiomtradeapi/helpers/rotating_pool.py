"""
Rotating Client Pool for Axiom Trade API

Provides multi-account and proxy rotation to avoid IP bans.
"""

import logging
import time
import random
import threading
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
import os


@dataclass
class AccountConfig:
    """Configuration for a single Axiom account"""
    auth_token: str
    refresh_token: str
    name: str = ""
    
    # Runtime state
    last_request_time: float = 0.0
    error_count: int = 0
    banned_until: float = 0.0
    is_permanently_banned: bool = False


@dataclass
class PoolConfig:
    """Configuration for the rotating pool"""
    rotation_interval: float = 30.0  # Seconds before switching to next client
    min_request_interval: float = 0.5  # Seconds between requests (rate limit)
    ban_cooldown: float = 300.0  # 5 minutes cooldown after errors
    max_errors_before_ban: int = 3  # Max consecutive errors before cooldown
    backoff_factor: float = 2.0  # Exponential backoff multiplier
    auto_switch_on_error: bool = True  # Auto-switch to next proxy on any error


class RotatingClientPool:
    """
    Manages multiple AxiomTradeClient instances with proxy rotation.
    
    Usage:
        pool = RotatingClientPool.from_env()
        client = pool.get_client()
        # Use client normally...
        pool.report_success(client)  # or pool.report_error(client)
    """
    
    def __init__(
        self,
        accounts: List[AccountConfig],
        proxies: List[str] = None,
        config: PoolConfig = None
    ):
        """
        Initialize the rotating pool.
        
        Args:
            accounts: List of AccountConfig with auth tokens
            proxies: List of proxy URLs (http://user:pass@host:port)
            config: Pool configuration
            
        Note: If proxies provided, creates one client PER PROXY (for IP rotation).
              Each proxy cycles through accounts round-robin.
        """
        from axiomtradeapi import AxiomTradeClient
        
        self.logger = logging.getLogger(__name__)
        self.config = config or PoolConfig()
        self.proxies = proxies or []
        self._lock = threading.Lock()
        self._current_index = 0
        self._client_switch_time = time.time()  # When current client was selected
        
        # Create clients - one per proxy for IP rotation
        self.clients: List[tuple[AxiomTradeClient, AccountConfig]] = []
        
        if self.proxies:
            # Create one client per proxy (for IP rotation)
            for i, proxy in enumerate(self.proxies):
                account = accounts[i % len(accounts)]  # Round-robin accounts
                try:
                    client = AxiomTradeClient(
                        auth_token=account.auth_token,
                        refresh_token=account.refresh_token,
                        proxy=proxy,
                        use_saved_tokens=False  # Don't save tokens - each client manages own
                    )
                    # Create unique account config for this proxy
                    proxy_account = AccountConfig(
                        auth_token=account.auth_token,
                        refresh_token=account.refresh_token,
                        name=f"{account.name}_proxy{i+1}"
                    )
                    self.clients.append((client, proxy_account))
                    proxy_display = proxy.split('@')[-1] if '@' in proxy else proxy
                    self.logger.info(f"✅ Created client #{i+1} with proxy: {proxy_display}")
                except Exception as e:
                    self.logger.error(f"❌ Failed to create client with proxy {proxy}: {e}")
        else:
            # No proxies - create one client per account
            for i, account in enumerate(accounts):
                try:
                    client = AxiomTradeClient(
                        auth_token=account.auth_token,
                        refresh_token=account.refresh_token,
                        proxy=None,
                        use_saved_tokens=False  # Don't save tokens
                    )
                    self.clients.append((client, account))
                    self.logger.info(f"✅ Created client for account '{account.name}' (no proxy)")
                except Exception as e:
                    self.logger.error(f"❌ Failed to create client for account '{account.name}': {e}")
        
        if not self.clients:
            raise ValueError("No valid clients could be created")
        
        self.logger.info(f"🔄 RotatingClientPool initialized with {len(self.clients)} clients (IP rotation: {'enabled' if self.proxies else 'disabled'})")
    
    @staticmethod
    def parse_proxy_file(filepath: str) -> List[str]:
        """
        Parse proxy file in ip:port:login:pass format (Webshare format).
        
        Args:
            filepath: Path to proxy file
            
        Returns:
            List of proxy URLs in http://login:pass@ip:port format
        """
        proxies = []
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    parts = line.split(':')
                    if len(parts) == 4:
                        # ip:port:login:pass format
                        ip, port, login, password = parts
                        proxy_url = f"http://{login}:{password}@{ip}:{port}"
                        proxies.append(proxy_url)
                    elif len(parts) == 2:
                        # ip:port format (no auth)
                        ip, port = parts
                        proxy_url = f"http://{ip}:{port}"
                        proxies.append(proxy_url)
        except Exception as e:
            logging.getLogger(__name__).error(f"Failed to load proxy file: {e}")
        
        return proxies
    
    @classmethod
    def from_env(cls, prefix: str = "AXIOM", proxy_file: str = None) -> "RotatingClientPool":
        """
        Create pool from environment variables.
        
        Expected format:
            AXIOM_AUTH_TOKEN_1=xxx
            AXIOM_REFRESH_TOKEN_1=xxx
            AXIOM_AUTH_TOKEN_2=xxx
            AXIOM_REFRESH_TOKEN_2=xxx
            ...
            AXIOM_PROXIES=http://user:pass@host1:port,http://host2:port
            AXIOM_PROXY_FILE=/path/to/proxies.txt
            
        Or for single account (backwards compatible):
            AUTH_TOKEN=xxx
            REFRESH_TOKEN=xxx
            
        Args:
            prefix: Environment variable prefix
            proxy_file: Path to proxy file (overrides env var)
        """
        accounts = []
        
        # Try numbered accounts first
        i = 1
        while True:
            # Handle empty prefix to avoid _AUTH_TOKEN_1
            pfx = f"{prefix}_" if prefix else ""
            
            auth = os.getenv(f"{pfx}AUTH_TOKEN_{i}")
            refresh = os.getenv(f"{pfx}REFRESH_TOKEN_{i}")
            
            # Fallback for alternative naming (e.g. AUTH_REFRESH_3)
            if not refresh:
                refresh = os.getenv(f"{pfx}AUTH_REFRESH_{i}")
            
            if not auth or not refresh:
                break
            
            accounts.append(AccountConfig(
                auth_token=auth,
                refresh_token=refresh,
                name=f"Account_{i}"
            ))
            i += 1
        
        # Fallback to single account format
        if not accounts:
            auth = os.getenv("AUTH_TOKEN")
            refresh = os.getenv("REFRESH_TOKEN")
            if auth and refresh:
                accounts.append(AccountConfig(
                    auth_token=auth,
                    refresh_token=refresh,
                    name="Default"
                ))
        
        if not accounts:
            raise ValueError(
                "No accounts found in environment. "
                "Set AXIOM_AUTH_TOKEN_1/AXIOM_REFRESH_TOKEN_1 or AUTH_TOKEN/REFRESH_TOKEN"
            )
        
        # Load proxies from file or env var
        proxies = []
        
        # Priority: direct file arg > env var file > env var list
        pfx = f"{prefix}_" if prefix else ""
        proxy_file_path = proxy_file or os.getenv(f"{pfx}PROXY_FILE")
        if proxy_file_path and os.path.exists(proxy_file_path):
            proxies = cls.parse_proxy_file(proxy_file_path)
            logging.getLogger(__name__).info(f"📦 Loaded {len(proxies)} proxies from file: {proxy_file_path}")
        else:
            pfx = f"{prefix}_" if prefix else ""
            proxies_str = os.getenv(f"{pfx}PROXIES", "")
            proxies = [p.strip() for p in proxies_str.split(",") if p.strip()]
        
        return cls(accounts=accounts, proxies=proxies)
    
    def get_client(self) -> "AxiomTradeClient":
        """
        Get client with time-based rotation.
        Switches to next client every rotation_interval seconds.
        
        Returns:
            AxiomTradeClient: Ready-to-use client
            
        Raises:
            RuntimeError: If no clients are available
        """
        from axiomtradeapi import AxiomTradeClient
        
        with self._lock:
            now = time.time()
            
            # Check if it's time to rotate to next client
            time_since_switch = now - self._client_switch_time
            if time_since_switch >= self.config.rotation_interval:
                old_index = self._current_index
                self._current_index = (self._current_index + 1) % len(self.clients)
                self._client_switch_time = now
                
                _, old_acc = self.clients[old_index]
                _, new_acc = self.clients[self._current_index]
                self.logger.info(f"🔄 Rotating client: {old_acc.name} → {new_acc.name} (after {time_since_switch:.0f}s)")
            
            # Get current client
            client, account = self.clients[self._current_index]
            
            # If current client is banned, try to find another
            # If current client is banned, try to find another
            if account.banned_until > now or account.is_permanently_banned:
                available_indices = []
                for i, (_, acc) in enumerate(self.clients):
                    if not acc.is_permanently_banned and acc.banned_until <= now:
                        available_indices.append(i)
                
                if available_indices:
                    # Pick next available (round-robin style relative to current)
                    # Find closest index > current_index, else min index
                    next_indices = [i for i in available_indices if i > self._current_index]
                    if next_indices:
                        self._current_index = next_indices[0]
                    else:
                        self._current_index = available_indices[0]
                        
                    self._client_switch_time = now
                    client, account = self.clients[self._current_index]
                    self.logger.info(f"🔄 Switched to non-banned client: {account.name}")
                else:
                    # Check if all are permanently banned
                    not_permanently_banned = [acc for _, acc in self.clients if not acc.is_permanently_banned]
                    if not not_permanently_banned:
                         raise RuntimeError("All proxies/accounts are permanently banned from Axiom API")

                    # All available are temporarily banned - wait for first to unban
                    min_ban_end = min(acc.banned_until for acc in not_permanently_banned)
                    wait_time = max(0, min_ban_end - now)
                    self.logger.warning(f"⚠️ All active clients temporarily banned, waiting {wait_time:.0f}s")
                    time.sleep(wait_time + 1)
                    return self.get_client()
            
            # Rate limiting
            time_since_last = now - account.last_request_time
            if time_since_last < self.config.min_request_interval:
                wait_time = self.config.min_request_interval - time_since_last
                time.sleep(wait_time)
            
            account.last_request_time = time.time()
            return client
    
    def report_success(self, client: "AxiomTradeClient") -> None:
        """Report successful request to reset error count"""
        for c, account in self.clients:
            if c is client:
                account.error_count = 0
                break
    
    def report_error(self, client: "AxiomTradeClient", is_rate_limit: bool = False) -> None:
        """
        Report failed request. Auto-switches to next proxy if enabled.
        
        Args:
            client: The client that had an error
            is_rate_limit: True if error was 429/403 (rate limit/ban)
        """
        with self._lock:
            for i, (c, account) in enumerate(self.clients):
                if c is client:
                    account.error_count += 1
                    
                    if is_rate_limit:
                        # Permanent ban for IP bans / 429s if configured or implied by severe error
                        account.is_permanently_banned = True
                        self.logger.error(f"⛔ {account.name} PERMANENTLY BANNED due to rate limit/IP ban")
                    elif account.error_count >= self.config.max_errors_before_ban:
                        cooldown = self.config.ban_cooldown * (self.config.backoff_factor ** (account.error_count - 1))
                        cooldown = min(cooldown, 3600)  # Max 1 hour
                        account.banned_until = time.time() + cooldown
                        self.logger.warning(
                            f"🚫 {account.name} temporarily banned for {cooldown:.0f}s "
                            f"(error_count={account.error_count})"
                        )
                    
                    # Auto-switch to next proxy on error
                    if self.config.auto_switch_on_error and len(self.clients) > 1:
                        # Find next non-permanently banned client
                        start_index = (i + 1) % len(self.clients)
                        for offset in range(len(self.clients)):
                            idx = (start_index + offset) % len(self.clients)
                            _, next_acc = self.clients[idx]
                            if not next_acc.is_permanently_banned:
                                self._current_index = idx
                                self._client_switch_time = time.time()
                                self.logger.info(f"⚡ Auto-switched proxy: {account.name} → {next_acc.name} (error triggered)")
                                break
                        else:
                             self.logger.critical("❌ All clients are permanently banned!")
                    break
    
    def force_switch(self) -> None:
        """Force switch to next available proxy immediately"""
        with self._lock:
            old_index = self._current_index
            self._current_index = (self._current_index + 1) % len(self.clients)
            self._client_switch_time = time.time()
            
            _, old_acc = self.clients[old_index]
            _, new_acc = self.clients[self._current_index]
            self.logger.info(f"⚡ Force-switched proxy: {old_acc.name} → {new_acc.name}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get pool statistics"""
        now = time.time()
        return {
            "total_clients": len(self.clients),
            "total_proxies": len(self.proxies),
            "clients": [
                {
                    "name": acc.name,
                    "error_count": acc.error_count,
                    "banned": acc.banned_until > now,
                    "banned_remaining": max(0, int(acc.banned_until - now)),
                    "is_permanently_banned": acc.is_permanently_banned
                }
                for _, acc in self.clients
            ]
        }
