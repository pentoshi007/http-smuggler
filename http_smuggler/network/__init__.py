"""Network modules for HTTP Smuggler."""

from .raw_socket import (
    RawHttpClient,
    AsyncRawHttpClient,
    RawResponse,
    build_raw_request,
    parse_url,
)
from .http2_client import (
    HTTP2RawClient,
    H2Response,
    H2ErrorCode,
    H2FrameType,
    build_h2_smuggling_body,
)
from .callback_server import (
    CallbackServer,
    AsyncCallbackServer,
    CallbackServerConfig,
    CapturedRequest,
    CaptureHandler,
    Fake101Handler,
    LootHandler,
    get_local_ip,
)

__all__ = [
    # HTTP/1.1
    "RawHttpClient",
    "AsyncRawHttpClient",
    "RawResponse",
    "build_raw_request",
    "parse_url",
    # HTTP/2
    "HTTP2RawClient",
    "H2Response",
    "H2ErrorCode",
    "H2FrameType",
    "build_h2_smuggling_body",
    # Callback servers
    "CallbackServer",
    "AsyncCallbackServer",
    "CallbackServerConfig",
    "CapturedRequest",
    "CaptureHandler",
    "Fake101Handler",
    "LootHandler",
    "get_local_ip",
]

