from axiomtradeapi.client import (
    AxiomTradeClient, quick_login_and_get_trending,
    get_trending_with_token, create_client_from_env,
)
from axiomtradeapi.auth.auth_manager import (
    AuthTokens, AuthManager, PerAccountTokenStorage, SecureTokenStorage,
    BROWSER_HEADERS, decode_jwt_payload, create_authenticated_session,
)
from axiomtradeapi.auth.login import AxiomAuth

# Version
__version__ = "2.0.0"

__all__ = [
    'AxiomTradeClient', 'AxiomAuth',
    'AuthTokens', 'AuthManager', 'PerAccountTokenStorage', 'SecureTokenStorage',
    'BROWSER_HEADERS', 'decode_jwt_payload',
    'create_client_from_env', 'create_authenticated_session',
    'quick_login_and_get_trending', 'get_trending_with_token',
    '__version__',
]