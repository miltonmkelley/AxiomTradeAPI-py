"""
Authentication and Cookie Manager for Axiom Trade API
Handles automatic login, token refresh, cookie management, and HTTP requests via curl_cffi.

All Axiom HTTP calls go through this module so that:
 - curl_cffi is used with impersonate="chrome" to avoid Cloudflare 418/403
 - Auth cookies are attached automatically
 - Token refresh is handled transparently (multi-URL fallback)
 - Proxy rotation is supported
"""

import json
import time
import logging
import os
import random
import hashlib
import base64
import threading
from pathlib import Path
from typing import Dict, Optional, Union, List
from dataclasses import dataclass
from datetime import datetime, timedelta

try:
    from cryptography.fernet import Fernet
    FERNET_AVAILABLE = True
except ImportError:
    FERNET_AVAILABLE = False

from curl_cffi import requests as cffi_requests


# ══════════════════════════════════════════════════════════════════════════════
# Constants
# ══════════════════════════════════════════════════════════════════════════════

BROWSER_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                  '(KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
    'Accept': 'application/json, text/plain, */*',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'Origin': 'https://axiom.trade',
    'Connection': 'keep-alive',
    'Referer': 'https://axiom.trade/',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-site',
}

# Axiom token-refresh endpoints (tried in order of priority)
REFRESH_URLS = [
    "https://api9.axiom.trade/refresh-access-token",
    "https://api10.axiom.trade/refresh-access-token",
    "https://api8.axiom.trade/refresh-access-token",
    "https://api3.axiom.trade/refresh-access-token",
    "https://api6.axiom.trade/refresh-access-token",
    "https://api.axiom.trade/refresh-access-token",
]

REFRESH_HEADERS_NO_BODY = {
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Content-Length": "0",
    "Origin": "https://axiom.trade",
    "Referer": "https://axiom.trade/",
    "User-Agent": BROWSER_HEADERS['User-Agent'],
    "sec-ch-ua": '"Chromium";v="135", "Not_A Brand";v="24"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-site",
}

REFRESH_HEADERS_JSON = {
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Content-Type": "application/json",
    "Origin": "https://axiom.trade",
    "Referer": "https://axiom.trade/",
    "User-Agent": BROWSER_HEADERS['User-Agent'],
    "sec-ch-ua": '"Chromium";v="135", "Not_A Brand";v="24"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-site",
}


# ══════════════════════════════════════════════════════════════════════════════
# JWT Helpers
# ══════════════════════════════════════════════════════════════════════════════

def _jwt_timestamp_seconds(value, default: float) -> float:
    """JWT exp/iat may be in seconds or milliseconds; always return seconds."""
    if value is None:
        return default
    try:
        t = float(value)
    except (TypeError, ValueError):
        return default
    if t > 1e10:  # milliseconds
        t = t / 1000.0
    return t


def decode_jwt_payload(token: str) -> dict:
    """Decode JWT token payload (without verification)."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


# ══════════════════════════════════════════════════════════════════════════════
# AuthTokens
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class AuthTokens:
    """Container for authentication tokens"""
    access_token: str
    refresh_token: str
    expires_at: float
    issued_at: float

    @property
    def is_expired(self) -> bool:
        """Check if token is expired (with 5 minute buffer)"""
        return time.time() >= (self.expires_at - 300)

    @property
    def needs_refresh(self) -> bool:
        """Check if token needs refresh (< 2 min left — Axiom gives 404 if refreshed too early)"""
        return time.time() >= (self.expires_at - 120)

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization"""
        return {
            'access_token': self.access_token,
            'refresh_token': self.refresh_token,
            'expires_at': self.expires_at,
            'issued_at': self.issued_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'AuthTokens':
        """Create from dictionary"""
        return cls(
            access_token=data['access_token'],
            refresh_token=data['refresh_token'],
            expires_at=data['expires_at'],
            issued_at=data.get('issued_at', data['expires_at'] - 3600),
        )

    @classmethod
    def from_jwt(cls, access_token: str, refresh_token: str) -> 'AuthTokens':
        """Create from raw JWT tokens, decoding expiry from the access token."""
        payload = decode_jwt_payload(access_token)
        now = time.time()
        return cls(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_at=_jwt_timestamp_seconds(payload.get("exp"), now + 3600),
            issued_at=_jwt_timestamp_seconds(payload.get("iat"), now),
        )


# ══════════════════════════════════════════════════════════════════════════════
# Token Storage
# ══════════════════════════════════════════════════════════════════════════════

class PerAccountTokenStorage:
    """Simple JSON token storage per-account (plain file, no encryption).
    
    Drop-in replacement for SecureTokenStorage when encryption is not needed.
    Tokens are stored as plain JSON — suitable for server-side scripts.
    """

    def __init__(self, path: str):
        self.path = path

    def save_tokens(self, tokens) -> bool:
        try:
            data = {
                "access_token": tokens.access_token,
                "refresh_token": tokens.refresh_token,
                "expires_at": tokens.expires_at,
                "issued_at": tokens.issued_at,
            }
            d = os.path.dirname(self.path)
            if d:
                os.makedirs(d, exist_ok=True)
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=0)
            return True
        except Exception:
            return False

    def load_tokens(self) -> Optional[AuthTokens]:
        try:
            if not os.path.isfile(self.path):
                return None
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return AuthTokens.from_dict(data)
        except Exception:
            return None

    def delete_tokens(self) -> bool:
        try:
            if os.path.isfile(self.path):
                os.unlink(self.path)
            return True
        except Exception:
            return False

    def has_saved_tokens(self) -> bool:
        return os.path.isfile(self.path)


class SecureTokenStorage:
    """Handles secure storage and retrieval of authentication tokens (encrypted)"""

    def __init__(self, storage_dir: str = None, token_filename: str = "tokens.enc"):
        if not FERNET_AVAILABLE:
            raise ImportError("cryptography package required for SecureTokenStorage. "
                              "Use PerAccountTokenStorage for plain JSON storage.")
        self.storage_dir = Path(storage_dir or Path.home() / '.axiomtradeapi')
        self.storage_dir.mkdir(exist_ok=True, mode=0o700)

        self.token_file = self.storage_dir / token_filename
        self.key_file = self.storage_dir / 'key.enc'

        self.logger = logging.getLogger(__name__)
        self._init_encryption_key()

    def _init_encryption_key(self):
        if self.key_file.exists():
            with open(self.key_file, 'rb') as f:
                self.key = f.read()
        else:
            self.key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(self.key)
            os.chmod(self.key_file, 0o600)
        self.cipher_suite = Fernet(self.key)

    def save_tokens(self, tokens: AuthTokens) -> bool:
        try:
            token_data = json.dumps(tokens.to_dict()).encode('utf-8')
            encrypted_data = self.cipher_suite.encrypt(token_data)
            with open(self.token_file, 'wb') as f:
                f.write(encrypted_data)
            os.chmod(self.token_file, 0o600)
            return True
        except Exception as e:
            self.logger.error(f"Failed to save tokens: {e}")
            return False

    def load_tokens(self) -> Optional[AuthTokens]:
        if not self.token_file.exists():
            return None
        try:
            with open(self.token_file, 'rb') as f:
                encrypted_data = f.read()
            decrypted_data = self.cipher_suite.decrypt(encrypted_data)
            token_data = json.loads(decrypted_data.decode('utf-8'))
            return AuthTokens.from_dict(token_data)
        except Exception as e:
            self.logger.error(f"Failed to load tokens: {e}")
            return None

    def delete_tokens(self) -> bool:
        try:
            if self.token_file.exists():
                self.token_file.unlink()
            return True
        except Exception as e:
            self.logger.error(f"Failed to delete tokens: {e}")
            return False

    def has_saved_tokens(self) -> bool:
        return self.token_file.exists()


# ══════════════════════════════════════════════════════════════════════════════
# Cookie Manager
# ══════════════════════════════════════════════════════════════════════════════

class CookieManager:
    """Manages cookies for HTTP requests"""

    def __init__(self):
        self.cookies = {}
        self.logger = logging.getLogger(__name__)

    def set_auth_cookies(self, auth_token: str, refresh_token: str) -> None:
        self.cookies['auth-access-token'] = auth_token
        self.cookies['auth-refresh-token'] = refresh_token

    def get_cookie_dict(self) -> dict:
        """Return cookies as a dict (for curl_cffi cookies= parameter)."""
        return dict(self.cookies)

    def get_cookie_header(self) -> str:
        """Get formatted cookie header string (legacy)."""
        if not self.cookies:
            return ""
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())

    def clear_auth_cookies(self) -> None:
        self.cookies.pop('auth-access-token', None)
        self.cookies.pop('auth-refresh-token', None)

    def has_auth_cookies(self) -> bool:
        return 'auth-access-token' in self.cookies and 'auth-refresh-token' in self.cookies


# ══════════════════════════════════════════════════════════════════════════════
# Auth Manager
# ══════════════════════════════════════════════════════════════════════════════

class AuthManager:
    """
    Manages authentication for Axiom Trade API.
    All HTTP requests go through curl_cffi with chrome impersonation.
    Token refresh uses the proven multi-URL fallback approach.
    """

    _refresh_lock = threading.Lock()
    _last_refresh_error_log_at = 0.0
    _REFRESH_ERROR_LOG_INTERVAL = 300

    def __init__(self, username: str = None, password: str = None,
                 auth_token: str = None, refresh_token: str = None,
                 storage_dir: str = None, use_saved_tokens: bool = True,
                 proxy: str = None, proxy_list: List[dict] = None,
                 token_filename: str = "tokens.enc"):
        """
        Initialize AuthManager.

        Args:
            username: Email for automatic login
            password: Password for automatic login
            auth_token: Existing auth token (optional)
            refresh_token: Existing refresh token (optional)
            storage_dir: Directory for secure token storage
            use_saved_tokens: Whether to load saved tokens (default: True)
            proxy: Single proxy URL (optional, legacy)
            proxy_list: List of proxy dicts [{"http": ..., "https": ...}, ...] for rotation
            token_filename: Name of the token file (default: tokens.enc)
        """
        self.username = username
        self.password = password
        self.base_url = "https://axiom.trade"
        self.use_saved_tokens = use_saved_tokens
        self.proxy = proxy
        self.proxy_list = proxy_list or []
        self._proxy_uses_left = 0
        self._current_proxy = None

        self.logger = logging.getLogger(__name__)
        self.cookie_manager = CookieManager()

        # Initialize token storage
        if storage_dir:
            # Use PerAccountTokenStorage for specified dirs (simpler, no encryption)
            token_path = os.path.join(storage_dir, token_filename)
            self.token_storage = PerAccountTokenStorage(token_path)
        elif FERNET_AVAILABLE:
            self.token_storage = SecureTokenStorage(token_filename=token_filename)
        else:
            self.token_storage = PerAccountTokenStorage(
                str(Path.home() / '.axiomtradeapi' / token_filename)
            )

        self.tokens: Optional[AuthTokens] = None

        # Try to load saved tokens first
        if use_saved_tokens:
            saved_tokens = self.token_storage.load_tokens()
            if saved_tokens and not saved_tokens.is_expired:
                self.tokens = saved_tokens
                self.cookie_manager.set_auth_cookies(
                    saved_tokens.access_token,
                    saved_tokens.refresh_token,
                )
                self.logger.info("Loaded valid saved tokens")
            elif saved_tokens and saved_tokens.is_expired:
                self.logger.info("Saved tokens are expired, will attempt refresh")
                self.tokens = saved_tokens

        # Initialize with provided tokens if given (overrides saved tokens)
        if auth_token and refresh_token:
            self.set_tokens_from_jwt(auth_token, refresh_token)

    @property
    def proxies(self):
        """Legacy getter for proxies attribute."""
        return self._get_random_proxy()

    @proxies.setter
    def proxies(self, value):
        """Legacy setter — allows `auth_manager.proxies = {...}`."""
        if value and isinstance(value, dict):
            self._current_proxy = value
            self._proxy_uses_left = 25

    def _get_random_proxy(self) -> Optional[dict]:
        """Return a proxy from the pool, rotating every 20–25 requests."""
        # Single proxy (legacy)
        if self.proxy and not self.proxy_list:
            return {"http": self.proxy, "https": self.proxy}
        # Pool rotation
        if not self.proxy_list:
            return None
        if self._current_proxy is None or self._proxy_uses_left <= 0:
            self._current_proxy = random.choice(self.proxy_list)
            self._proxy_uses_left = random.randint(20, 25)
        self._proxy_uses_left -= 1
        return self._current_proxy

    # ── Token management ─────────────────────────────────────────────────────

    def _set_tokens(self, auth_token: str, refresh_token: str,
                    expires_in: int = 3600, save_tokens: bool = True) -> None:
        """Set authentication tokens (legacy — fixed expiry)."""
        current_time = time.time()
        self.tokens = AuthTokens(
            access_token=auth_token,
            refresh_token=refresh_token,
            expires_at=current_time + expires_in,
            issued_at=current_time,
        )
        self.cookie_manager.set_auth_cookies(auth_token, refresh_token)
        if save_tokens and self.use_saved_tokens:
            self.token_storage.save_tokens(self.tokens)
        self.logger.info("Authentication tokens updated successfully")

    def set_tokens_from_jwt(self, auth_token: str, refresh_token: str,
                            save: bool = True) -> AuthTokens:
        """Set tokens by decoding JWT to extract real expires_at / issued_at."""
        self.tokens = AuthTokens.from_jwt(auth_token, refresh_token)
        self.cookie_manager.set_auth_cookies(auth_token, refresh_token)
        if save and self.use_saved_tokens:
            self.token_storage.save_tokens(self.tokens)
        self.logger.info("Tokens set from JWT (expires_at=%s)", 
                         time.strftime('%H:%M:%S', time.localtime(self.tokens.expires_at)))
        return self.tokens

    # ── Token refresh (multi-URL, curl_cffi) ─────────────────────────────────

    def refresh_tokens(self) -> bool:
        """
        Refresh authentication tokens using curl_cffi with multi-URL fallback.
        Thread-safe via _refresh_lock.
        """
        if not self.tokens or not self.tokens.refresh_token:
            self.logger.error("No refresh token available")
            return False

        cookies = {
            "auth-refresh-token": self.tokens.refresh_token,
            "auth-access-token": self.tokens.access_token,
        }
        payload_v = {"v": int(time.time() * 1000)}

        def _parse_response(response):
            if response.status_code != 200:
                return None
            new_access = response.cookies.get("auth-access-token")
            new_refresh = response.cookies.get("auth-refresh-token")
            if new_access:
                use_refresh = new_refresh or self.tokens.refresh_token
                payload = decode_jwt_payload(new_access)
                now = time.time()
                return AuthTokens(
                    access_token=new_access,
                    refresh_token=use_refresh,
                    expires_at=_jwt_timestamp_seconds(payload.get("exp"), now + 3600),
                    issued_at=_jwt_timestamp_seconds(payload.get("iat"), now),
                )
            try:
                data = response.json()
                new_access = (data.get("accessToken") or data.get("auth-access-token")
                              or data.get("access_token"))
                new_refresh = (data.get("refreshToken") or data.get("auth-refresh-token")
                               or data.get("refresh_token") or self.tokens.refresh_token)
                if new_access:
                    payload = decode_jwt_payload(new_access)
                    now = time.time()
                    return AuthTokens(
                        access_token=new_access,
                        refresh_token=new_refresh,
                        expires_at=_jwt_timestamp_seconds(payload.get("exp"), now + 3600),
                        issued_at=_jwt_timestamp_seconds(payload.get("iat"), now),
                    )
            except (json.JSONDecodeError, TypeError, AttributeError):
                pass
            return None

        def _try_refresh(use_proxies):
            nonlocal last_status, last_text
            for url in REFRESH_URLS:
                # Attempt 1: empty body
                try:
                    resp = cffi_requests.post(
                        url, headers=REFRESH_HEADERS_NO_BODY, cookies=cookies,
                        timeout=30, proxies=use_proxies, impersonate="chrome",
                    )
                    last_status, last_text = resp.status_code, resp.text[:200]
                    pair = _parse_response(resp)
                    if pair:
                        return pair
                    if resp.status_code in (200, 201):
                        return None
                except Exception:
                    continue
                # Attempt 2: JSON body with v= timestamp
                try:
                    resp = cffi_requests.post(
                        url, headers=REFRESH_HEADERS_JSON, cookies=cookies,
                        json=payload_v, timeout=30, proxies=use_proxies,
                        impersonate="chrome",
                    )
                    last_status, last_text = resp.status_code, resp.text[:200]
                    pair = _parse_response(resp)
                    if pair:
                        return pair
                    if resp.status_code in (200, 201):
                        return None
                except Exception:
                    continue
            return None

        try:
            with self._refresh_lock:
                self.logger.info("Refreshing authentication tokens...")
                last_status = last_text = None
                proxies = self._get_random_proxy()
                pair = _try_refresh(proxies)
                if not pair and proxies:
                    pair = _try_refresh(None)  # fallback without proxy
                if pair:
                    self.tokens = pair
                    self.cookie_manager.set_auth_cookies(pair.access_token, pair.refresh_token)
                    if self.use_saved_tokens:
                        self.token_storage.save_tokens(pair)
                    self.logger.info("✅ Tokens refreshed successfully!")
                    return True

                now = time.time()
                if now - self._last_refresh_error_log_at >= self._REFRESH_ERROR_LOG_INTERVAL:
                    AuthManager._last_refresh_error_log_at = now
                    if last_status == 404:
                        self.logger.warning(
                            "Token refresh 404 — access_token still valid? "
                            "Когда истечёт — обнови cookies в .env",
                        )
                    else:
                        self.logger.error(
                            "Token refresh failed: %s - %s (обнови cookies в .env)",
                            last_status or "?", last_text or "?"
                        )
                return False
        except Exception as e:
            self.logger.error("Token refresh error: %s", e)
            return False

    # ── Authentication ────────────────────────────────────────────────────────

    def authenticate(self) -> bool:
        """Authenticate with username/password using Axiom's OTP login flow."""
        if not self.username or not self.password:
            self.logger.error("Username and password required for authentication")
            return False
        try:
            self.logger.info("Starting Axiom Trade authentication...")
            otp_jwt_token = self._login_step1()
            if not otp_jwt_token:
                return False
            otp_code = input("Enter the OTP code sent to your email: ")
            if not otp_code:
                self.logger.error("OTP code is required")
                return False
            return self._login_step2(otp_jwt_token, otp_code)
        except Exception as e:
            self.logger.error(f"❌ Authentication error: {e}")
            return False

    def _get_b64_password(self, password: str) -> str:
        SALT = bytes([
            217, 3, 161, 123, 53, 200, 206, 36, 143, 2, 220, 252, 240, 109, 204, 23,
            217, 174, 79, 158, 18, 76, 149, 117, 73, 40, 207, 77, 34, 194, 196, 163
        ])
        derived_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), SALT, 600_000, dklen=32)
        return base64.b64encode(derived_key).decode('ascii')

    def _login_step1(self) -> Optional[str]:
        from axiomtradeapi.urls import AAllBaseUrls, AxiomTradeApiUrls
        b64_password = self._get_b64_password(self.password)
        url = f'{AAllBaseUrls.BASE_URL_v6}{AxiomTradeApiUrls.LOGIN_STEP1}'
        headers = {**BROWSER_HEADERS, 'Content-Type': 'application/json', 'Cookie': 'auth-otp-login-token='}
        data = {"email": self.username, "b64Password": b64_password}
        try:
            resp = cffi_requests.post(url, headers=headers, json=data, timeout=30, impersonate="chrome")
            if resp.status_code == 200:
                otp_token = resp.cookies.get('auth-otp-login-token')
                if otp_token:
                    return otp_token
                self.logger.error("auth-otp-login-token not found in cookies!")
            else:
                self.logger.error(f"Login step 1 failed: {resp.status_code} - {resp.text}")
        except Exception as e:
            self.logger.error(f"Login step 1 error: {e}")
        return None

    def _login_step2(self, otp_jwt_token: str, otp_code: str) -> bool:
        from axiomtradeapi.urls import AAllBaseUrls, AxiomTradeApiUrls
        b64_password = self._get_b64_password(self.password)
        url = f'{AAllBaseUrls.BASE_URL_v3}{AxiomTradeApiUrls.LOGIN_STEP2}'
        headers = {**BROWSER_HEADERS, 'Content-Type': 'application/json',
                   'Cookie': f'auth-otp-login-token={otp_jwt_token}'}
        data = {"code": otp_code, "email": self.username, "b64Password": b64_password}
        try:
            resp = cffi_requests.post(url, headers=headers, json=data, timeout=30, impersonate="chrome")
            if resp.status_code == 200:
                auth_token = resp.cookies.get('auth-access-token')
                refresh_token = resp.cookies.get('auth-refresh-token')
                if auth_token and refresh_token:
                    self.set_tokens_from_jwt(auth_token, refresh_token)
                    self.logger.info("✅ Authentication successful!")
                    return True
                try:
                    rd = resp.json()
                    auth_token = rd.get('accessToken') or rd.get('auth-access-token')
                    refresh_token = rd.get('refreshToken') or rd.get('auth-refresh-token')
                    if auth_token and refresh_token:
                        self.set_tokens_from_jwt(auth_token, refresh_token)
                        self.logger.info("✅ Authentication successful!")
                        return True
                except Exception:
                    pass
                self.logger.error("❌ No authentication tokens found in response")
            else:
                self.logger.error(f"❌ Login step 2 failed: {resp.status_code} - {resp.text}")
        except Exception as e:
            self.logger.error(f"❌ Login step 2 error: {e}")
        return False

    # ── Ensuring valid auth ───────────────────────────────────────────────────

    def ensure_valid_authentication(self) -> bool:
        if not self.tokens:
            if self.username and self.password:
                return self.authenticate()
            self.logger.error("No authentication tokens and no credentials provided")
            return False
        if not self.tokens.is_expired:
            # Auto-refresh when < 2 min left
            if self.tokens.needs_refresh:
                self.refresh_tokens()
            return True
        if self.refresh_tokens():
            return True
        if self.username and self.password:
            return self.authenticate()
        self.logger.error("Cannot refresh tokens and no credentials for re-authentication")
        return False

    def is_authenticated(self) -> bool:
        return (self.tokens is not None and
                not self.tokens.is_expired and
                self.cookie_manager.has_auth_cookies())

    # ── HTTP requests via curl_cffi ──────────────────────────────────────────

    def make_authenticated_request(self, method: str, url: str, **kwargs) -> cffi_requests.Response:
        """
        Make an authenticated HTTP request using curl_cffi with chrome impersonation.

        Auth cookies are sent via the cookies= parameter.
        Proxy rotation is applied automatically.

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Request URL
            **kwargs: Additional arguments for curl_cffi requests

        Returns:
            curl_cffi Response object
        """
        # Ensure we have valid authentication
        self.ensure_valid_authentication()

        # Merge headers
        headers = {**BROWSER_HEADERS}
        user_headers = kwargs.pop('headers', None)
        if user_headers:
            headers.update(user_headers)

        # Auth cookies
        cookies = self.cookie_manager.get_cookie_dict()
        user_cookies = kwargs.pop('cookies', None)
        if user_cookies:
            cookies.update(user_cookies)

        # Proxy — use provided or rotate from pool
        proxies = kwargs.pop('proxies', None) or self._get_random_proxy()

        # Default timeout
        timeout = kwargs.pop('timeout', 30)

        self.logger.info(f"🌐 {method} {url}")

        t0 = time.time()
        with cffi_requests.Session(impersonate="chrome") as session:
            response = session.request(
                method, url, headers=headers, cookies=cookies,
                proxies=proxies, timeout=timeout, **kwargs,
            )
        elapsed_ms = int((time.time() - t0) * 1000)
        self.logger.info(f"   → {response.status_code} ({elapsed_ms}ms) {url[:80]}")
        return response

    def authenticated_get(self, url: str, **kwargs) -> Optional[cffi_requests.Response]:
        """Convenience GET with error handling (returns None on failure)."""
        try:
            resp = self.make_authenticated_request('GET', url, **kwargs)
            if resp.status_code != 200:
                self.logger.warning(f"⚠️ GET {url[:80]}... → {resp.status_code}")
            return resp
        except Exception as e:
            self.logger.warning(f"⚠️ GET {url[:80]}... failed: {e}")
            return None

    def authenticated_post(self, url: str, **kwargs) -> Optional[cffi_requests.Response]:
        """Convenience POST with error handling (returns None on failure)."""
        try:
            resp = self.make_authenticated_request('POST', url, **kwargs)
            if resp.status_code != 200:
                self.logger.warning(f"⚠️ POST {url[:80]}... → {resp.status_code}")
            return resp
        except Exception as e:
            self.logger.warning(f"⚠️ POST {url[:80]}... failed: {e}")
            return None

    # ── Helpers (legacy compat) ───────────────────────────────────────────────

    def get_authenticated_headers(self, additional_headers: Dict[str, str] = None) -> Dict[str, str]:
        """Legacy: get headers with cookie header string."""
        self.ensure_valid_authentication()
        headers = {**BROWSER_HEADERS}
        cookie_header = self.cookie_manager.get_cookie_header()
        if cookie_header:
            headers["Cookie"] = cookie_header
        if additional_headers:
            headers.update(additional_headers)
        return headers

    def logout(self) -> None:
        self.tokens = None
        self.cookie_manager.clear_auth_cookies()
        if self.use_saved_tokens:
            self.token_storage.delete_tokens()
        self.logger.info("Logged out successfully")

    def clear_saved_tokens(self) -> bool:
        return self.token_storage.delete_tokens()

    def has_saved_tokens(self) -> bool:
        return self.token_storage.has_saved_tokens()

    def get_token_info(self) -> Dict[str, Union[str, bool, float]]:
        if not self.tokens:
            return {"authenticated": False}
        return {
            "authenticated": True,
            "access_token_preview": self.tokens.access_token[:20] + "..." if self.tokens.access_token else None,
            "expires_at": self.tokens.expires_at,
            "issued_at": self.tokens.issued_at,
            "is_expired": self.tokens.is_expired,
            "needs_refresh": self.tokens.needs_refresh,
            "time_until_expiry": max(0, self.tokens.expires_at - time.time()),
        }

    def get_tokens(self) -> Optional[AuthTokens]:
        return self.tokens


# ══════════════════════════════════════════════════════════════════════════════
# Convenience factory
# ══════════════════════════════════════════════════════════════════════════════

def create_authenticated_session(username: str = None, password: str = None,
                                 auth_token: str = None, refresh_token: str = None,
                                 storage_dir: str = None, use_saved_tokens: bool = True,
                                 token_filename: str = "tokens.enc") -> AuthManager:
    """Create an authenticated session (legacy convenience function)."""
    return AuthManager(
        username=username, password=password,
        auth_token=auth_token, refresh_token=refresh_token,
        storage_dir=storage_dir, use_saved_tokens=use_saved_tokens,
        token_filename=token_filename,
    )
