"""HTTP/2 raw client for HTTP Smuggler.

Uses hyperframe for low-level HTTP/2 frame manipulation, allowing us to craft
malformed requests that bypass h2 library validation for smuggling testing.
"""

import ssl
import asyncio
import struct
from typing import Optional, List, Tuple, Dict, Any
from dataclasses import dataclass, field
from enum import IntEnum

from hyperframe.frame import (
    Frame,
    HeadersFrame,
    DataFrame,
    SettingsFrame,
    WindowUpdateFrame,
    GoAwayFrame,
    PingFrame,
    PriorityFrame,
    RstStreamFrame,
    ContinuationFrame,
)
from hpack import Encoder, Decoder, HPACKDecodingError

from http_smuggler.core.config import NetworkConfig
from http_smuggler.core.exceptions import (
    ConnectionError,
    ConnectionTimeoutError,
    SSLError,
    HTTP2Error,
)


class H2ErrorCode(IntEnum):
    """HTTP/2 error codes."""
    NO_ERROR = 0x0
    PROTOCOL_ERROR = 0x1
    INTERNAL_ERROR = 0x2
    FLOW_CONTROL_ERROR = 0x3
    SETTINGS_TIMEOUT = 0x4
    STREAM_CLOSED = 0x5
    FRAME_SIZE_ERROR = 0x6
    REFUSED_STREAM = 0x7
    CANCEL = 0x8
    COMPRESSION_ERROR = 0x9
    CONNECT_ERROR = 0xa
    ENHANCE_YOUR_CALM = 0xb
    INADEQUATE_SECURITY = 0xc
    HTTP_1_1_REQUIRED = 0xd


class H2FrameType(IntEnum):
    """HTTP/2 frame types."""
    DATA = 0x0
    HEADERS = 0x1
    PRIORITY = 0x2
    RST_STREAM = 0x3
    SETTINGS = 0x4
    PUSH_PROMISE = 0x5
    PING = 0x6
    GOAWAY = 0x7
    WINDOW_UPDATE = 0x8
    CONTINUATION = 0x9


# HTTP/2 connection preface
H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# Default settings
DEFAULT_SETTINGS = {
    0x1: 4096,      # HEADER_TABLE_SIZE
    0x2: 1,         # ENABLE_PUSH
    0x3: 100,       # MAX_CONCURRENT_STREAMS
    0x4: 65535,     # INITIAL_WINDOW_SIZE
    0x5: 16384,     # MAX_FRAME_SIZE
    0x6: 8192,      # MAX_HEADER_LIST_SIZE
}


@dataclass
class H2Response:
    """HTTP/2 response data."""
    stream_id: int
    status: Optional[int] = None
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    
    # Frame-level data
    frames_received: List[Frame] = field(default_factory=list)
    
    # Error info
    error_code: Optional[int] = None
    error_message: Optional[str] = None
    
    @property
    def is_complete(self) -> bool:
        """Check if response is complete (END_STREAM received)."""
        for frame in self.frames_received:
            if hasattr(frame, 'flags') and 'END_STREAM' in frame.flags:
                return True
        return False


class HTTP2RawClient:
    """Low-level HTTP/2 client for crafting malformed requests.
    
    Unlike the h2 library, this client allows us to:
    - Inject arbitrary headers (including forbidden ones like content-length)
    - Send malformed frames
    - Craft requests that violate HTTP/2 semantics
    """
    
    def __init__(self, config: Optional[NetworkConfig] = None):
        self.config = config or NetworkConfig()
        self.encoder = Encoder()
        self.decoder = Decoder()
        
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._connected = False
        self._host: Optional[str] = None
        self._port: Optional[int] = None
        
        # Stream management
        self._next_stream_id = 1
        self._streams: Dict[int, H2Response] = {}
        
        # Connection state
        self._server_settings: Dict[int, int] = {}
        self._local_settings: Dict[int, int] = DEFAULT_SETTINGS.copy()
        self._goaway_received = False
    
    async def connect(
        self,
        host: str,
        port: int = 443,
        server_hostname: Optional[str] = None,
    ) -> None:
        """Establish HTTP/2 connection with TLS and ALPN.
        
        Args:
            host: Target host
            port: Target port (default 443 for HTTPS)
            server_hostname: SNI hostname (defaults to host)
        """
        await self.close()
        
        # Create SSL context with h2 ALPN
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(["h2"])
        
        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host, port,
                    ssl=context,
                    server_hostname=server_hostname or host,
                ),
                timeout=self.config.connect_timeout,
            )
        except asyncio.TimeoutError:
            raise ConnectionTimeoutError(host, port, self.config.connect_timeout, "connect")
        except ssl.SSLError as e:
            raise SSLError(host, str(e))
        except Exception as e:
            raise ConnectionError(f"Failed to connect to {host}:{port}: {e}")
        
        # Verify ALPN negotiation
        ssl_object = self._writer.get_extra_info('ssl_object')
        if ssl_object:
            alpn = ssl_object.selected_alpn_protocol()
            if alpn != "h2":
                await self.close()
                raise HTTP2Error(f"ALPN negotiation failed: {alpn}")
        
        self._host = host
        self._port = port
        self._connected = True
        
        # Send connection preface
        await self._send_preface()
    
    async def _send_preface(self) -> None:
        """Send HTTP/2 connection preface and initial SETTINGS."""
        # Connection preface
        self._writer.write(H2_PREFACE)
        
        # SETTINGS frame
        settings_frame = SettingsFrame(stream_id=0)
        for setting_id, value in self._local_settings.items():
            settings_frame.settings[setting_id] = value
        
        self._writer.write(settings_frame.serialize())
        await self._writer.drain()
        
        # Read server's SETTINGS
        await self._read_and_process_frames(timeout=5.0, expect_settings=True)
    
    def _allocate_stream_id(self) -> int:
        """Allocate a new stream ID."""
        stream_id = self._next_stream_id
        self._next_stream_id += 2  # Client streams are odd
        return stream_id
    
    def build_headers_frame(
        self,
        headers: List[Tuple[str, str]],
        stream_id: Optional[int] = None,
        end_stream: bool = False,
        end_headers: bool = True,
    ) -> Tuple[bytes, int]:
        """Build a HEADERS frame with HPACK encoding.
        
        Args:
            headers: List of (name, value) header tuples
            stream_id: Stream ID (auto-allocated if None)
            end_stream: Set END_STREAM flag
            end_headers: Set END_HEADERS flag
        
        Returns:
            Tuple of (serialized frame, stream_id)
        """
        if stream_id is None:
            stream_id = self._allocate_stream_id()
        
        # Encode headers with HPACK
        encoded = self.encoder.encode(headers)
        
        frame = HeadersFrame(stream_id=stream_id)
        frame.data = encoded
        
        if end_headers:
            frame.flags.add('END_HEADERS')
        if end_stream:
            frame.flags.add('END_STREAM')
        
        return frame.serialize(), stream_id
    
    def build_data_frame(
        self,
        data: bytes,
        stream_id: int,
        end_stream: bool = True,
    ) -> bytes:
        """Build a DATA frame.
        
        Args:
            data: Payload data
            stream_id: Stream ID
            end_stream: Set END_STREAM flag
        
        Returns:
            Serialized frame
        """
        frame = DataFrame(stream_id=stream_id)
        frame.data = data
        
        if end_stream:
            frame.flags.add('END_STREAM')
        
        return frame.serialize()
    
    def build_raw_frame(
        self,
        frame_type: int,
        flags: int,
        stream_id: int,
        payload: bytes,
    ) -> bytes:
        """Build a raw frame with arbitrary content.
        
        This bypasses hyperframe validation for testing malformed frames.
        
        Args:
            frame_type: Frame type byte
            flags: Flags byte
            stream_id: Stream ID (31 bits)
            payload: Raw payload bytes
        
        Returns:
            Serialized frame
        """
        length = len(payload)
        header = struct.pack(
            ">I",
            (length << 8) | frame_type,
        )[:3]  # 3 bytes for length
        header += struct.pack(">B", frame_type)
        header += struct.pack(">B", flags)
        header += struct.pack(">I", stream_id & 0x7FFFFFFF)
        
        # Correct format: length (3 bytes) + type (1 byte) + flags (1 byte) + stream_id (4 bytes)
        frame_header = struct.pack(">I", length)[1:4]  # 3 bytes for length
        frame_header += struct.pack(">B", frame_type)
        frame_header += struct.pack(">B", flags)
        frame_header += struct.pack(">I", stream_id & 0x7FFFFFFF)
        
        return frame_header + payload
    
    async def send_request(
        self,
        method: str,
        path: str,
        authority: str,
        headers: Optional[List[Tuple[str, str]]] = None,
        body: Optional[bytes] = None,
        inject_content_length: Optional[int] = None,
        inject_transfer_encoding: Optional[str] = None,
    ) -> int:
        """Send an HTTP/2 request.
        
        Args:
            method: HTTP method
            path: Request path
            authority: Authority (host:port)
            headers: Additional headers
            body: Request body
            inject_content_length: Inject Content-Length header (for H2.CL)
            inject_transfer_encoding: Inject Transfer-Encoding header (for H2.TE)
        
        Returns:
            Stream ID
        """
        if not self._connected:
            raise ConnectionError("Not connected")
        
        # Build pseudo-headers
        all_headers = [
            (":method", method),
            (":path", path),
            (":scheme", "https"),
            (":authority", authority),
        ]
        
        # Add custom headers
        if headers:
            all_headers.extend(headers)
        
        # Inject smuggling headers (these are forbidden in HTTP/2 but we send anyway)
        if inject_content_length is not None:
            all_headers.append(("content-length", str(inject_content_length)))
        
        if inject_transfer_encoding is not None:
            all_headers.append(("transfer-encoding", inject_transfer_encoding))
        
        # Build and send HEADERS frame
        has_body = body is not None and len(body) > 0
        headers_frame, stream_id = self.build_headers_frame(
            all_headers,
            end_stream=not has_body,
        )
        
        self._streams[stream_id] = H2Response(stream_id=stream_id)
        
        self._writer.write(headers_frame)
        await self._writer.drain()
        
        # Send DATA frame if there's a body
        if has_body:
            data_frame = self.build_data_frame(body, stream_id, end_stream=True)
            self._writer.write(data_frame)
            await self._writer.drain()
        
        return stream_id
    
    async def send_smuggling_request(
        self,
        headers: List[Tuple[str, str]],
        body: Optional[bytes] = None,
        crlf_injection: Optional[Dict[str, str]] = None,
    ) -> int:
        """Send a request designed for HTTP/2 smuggling.
        
        Args:
            headers: Full headers including pseudo-headers
            body: Request body
            crlf_injection: Dict mapping header names to values with CRLF injection
        
        Returns:
            Stream ID
        """
        if not self._connected:
            raise ConnectionError("Not connected")
        
        # Apply CRLF injection if specified
        final_headers = []
        for name, value in headers:
            if crlf_injection and name in crlf_injection:
                # Inject CRLF into header value
                value = crlf_injection[name]
            final_headers.append((name, value))
        
        has_body = body is not None and len(body) > 0
        headers_frame, stream_id = self.build_headers_frame(
            final_headers,
            end_stream=not has_body,
        )
        
        self._streams[stream_id] = H2Response(stream_id=stream_id)
        
        self._writer.write(headers_frame)
        await self._writer.drain()
        
        if has_body:
            data_frame = self.build_data_frame(body, stream_id, end_stream=True)
            self._writer.write(data_frame)
            await self._writer.drain()
        
        return stream_id
    
    async def send_raw_frames(self, frames: List[bytes]) -> None:
        """Send raw pre-built frames.
        
        Args:
            frames: List of serialized frames
        """
        if not self._connected:
            raise ConnectionError("Not connected")
        
        for frame in frames:
            self._writer.write(frame)
        await self._writer.drain()
    
    async def receive_response(
        self,
        stream_id: int,
        timeout: Optional[float] = None,
    ) -> H2Response:
        """Receive response for a stream.
        
        Args:
            stream_id: Stream ID to receive response for
            timeout: Read timeout
        
        Returns:
            H2Response with headers and body
        """
        timeout = timeout or self.config.read_timeout
        
        if stream_id not in self._streams:
            self._streams[stream_id] = H2Response(stream_id=stream_id)
        
        response = self._streams[stream_id]
        
        # Read frames until END_STREAM
        await self._read_and_process_frames(
            timeout=timeout,
            target_stream=stream_id,
        )
        
        return response
    
    async def _read_and_process_frames(
        self,
        timeout: float = 10.0,
        target_stream: Optional[int] = None,
        expect_settings: bool = False,
    ) -> None:
        """Read and process incoming frames.
        
        Args:
            timeout: Read timeout
            target_stream: Stop when this stream receives END_STREAM
            expect_settings: True if expecting initial SETTINGS
        """
        end_time = asyncio.get_event_loop().time() + timeout
        
        while True:
            remaining = end_time - asyncio.get_event_loop().time()
            if remaining <= 0:
                break
            
            try:
                # Read frame header (9 bytes)
                header = await asyncio.wait_for(
                    self._reader.readexactly(9),
                    timeout=remaining,
                )
            except asyncio.TimeoutError:
                break
            except asyncio.IncompleteReadError:
                break
            
            # Parse frame header
            length = (header[0] << 16) | (header[1] << 8) | header[2]
            frame_type = header[3]
            flags = header[4]
            stream_id = struct.unpack(">I", header[5:9])[0] & 0x7FFFFFFF
            
            # Read payload
            if length > 0:
                try:
                    payload = await asyncio.wait_for(
                        self._reader.readexactly(length),
                        timeout=remaining,
                    )
                except asyncio.TimeoutError:
                    break
                except asyncio.IncompleteReadError:
                    break
            else:
                payload = b""
            
            # Process frame
            await self._process_frame(frame_type, flags, stream_id, payload)
            
            # Check if we should stop
            if target_stream is not None:
                response = self._streams.get(target_stream)
                if response and response.is_complete:
                    break
            
            if expect_settings and self._server_settings:
                break
    
    async def _process_frame(
        self,
        frame_type: int,
        flags: int,
        stream_id: int,
        payload: bytes,
    ) -> None:
        """Process a received frame.
        
        Args:
            frame_type: Frame type
            flags: Frame flags
            stream_id: Stream ID
            payload: Frame payload
        """
        if frame_type == H2FrameType.SETTINGS:
            if stream_id == 0 and not (flags & 0x1):  # Not ACK
                # Parse settings
                for i in range(0, len(payload), 6):
                    if i + 6 <= len(payload):
                        setting_id = struct.unpack(">H", payload[i:i+2])[0]
                        value = struct.unpack(">I", payload[i+2:i+6])[0]
                        self._server_settings[setting_id] = value
                
                # Send SETTINGS ACK
                ack_frame = SettingsFrame(stream_id=0)
                ack_frame.flags.add('ACK')
                self._writer.write(ack_frame.serialize())
                await self._writer.drain()
        
        elif frame_type == H2FrameType.HEADERS:
            if stream_id in self._streams:
                response = self._streams[stream_id]
                
                # Create a dummy frame for tracking
                frame = HeadersFrame(stream_id=stream_id)
                if flags & 0x1:
                    frame.flags.add('END_STREAM')
                if flags & 0x4:
                    frame.flags.add('END_HEADERS')
                response.frames_received.append(frame)
                
                # Decode headers
                try:
                    headers = self.decoder.decode(payload)
                    for name, value in headers:
                        if name == ":status":
                            response.status = int(value)
                        else:
                            response.headers[name] = value
                except HPACKDecodingError:
                    pass
        
        elif frame_type == H2FrameType.DATA:
            if stream_id in self._streams:
                response = self._streams[stream_id]
                response.body += payload
                
                frame = DataFrame(stream_id=stream_id)
                if flags & 0x1:
                    frame.flags.add('END_STREAM')
                response.frames_received.append(frame)
        
        elif frame_type == H2FrameType.RST_STREAM:
            if stream_id in self._streams:
                error_code = struct.unpack(">I", payload[:4])[0] if len(payload) >= 4 else 0
                self._streams[stream_id].error_code = error_code
                self._streams[stream_id].error_message = f"RST_STREAM: {error_code}"
        
        elif frame_type == H2FrameType.GOAWAY:
            self._goaway_received = True
            if len(payload) >= 8:
                last_stream_id = struct.unpack(">I", payload[:4])[0]
                error_code = struct.unpack(">I", payload[4:8])[0]
        
        elif frame_type == H2FrameType.PING:
            if not (flags & 0x1):  # Not ACK
                # Send PING ACK
                ping_frame = PingFrame(stream_id=0)
                ping_frame.flags.add('ACK')
                ping_frame.opaque_data = payload[:8] if len(payload) >= 8 else payload
                self._writer.write(ping_frame.serialize())
                await self._writer.drain()
        
        elif frame_type == H2FrameType.WINDOW_UPDATE:
            pass  # Ignore for now
    
    async def close(self) -> None:
        """Close the HTTP/2 connection."""
        if self._writer:
            try:
                # Send GOAWAY
                goaway = GoAwayFrame(stream_id=0)
                goaway.last_stream_id = self._next_stream_id - 2
                goaway.error_code = H2ErrorCode.NO_ERROR
                self._writer.write(goaway.serialize())
                await self._writer.drain()
            except Exception:
                pass
            
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
        
        self._reader = None
        self._writer = None
        self._connected = False
        self._streams.clear()
        self._next_stream_id = 1
        self._server_settings.clear()
        self._goaway_received = False
        
        # Reset HPACK state
        self.encoder = Encoder()
        self.decoder = Decoder()
    
    @property
    def is_connected(self) -> bool:
        """Check if connection is active."""
        return self._connected and self._writer is not None and not self._goaway_received
    
    async def __aenter__(self) -> "HTTP2RawClient":
        return self
    
    async def __aexit__(self, *args) -> None:
        await self.close()


def build_h2_smuggling_body(
    method: str,
    path: str,
    host: str,
    headers: Optional[Dict[str, str]] = None,
    body: Optional[bytes] = None,
) -> bytes:
    """Build an HTTP/1.1 request to embed in HTTP/2 body for smuggling.
    
    When HTTP/2 is downgraded to HTTP/1.1 by a proxy, this embedded
    request can be smuggled to the backend.
    
    Args:
        method: HTTP method
        path: Request path
        host: Host header
        headers: Additional headers
        body: Request body
    
    Returns:
        HTTP/1.1 request bytes
    """
    headers = headers or {}
    
    request = f"{method} {path} HTTP/1.1\r\n"
    request += f"Host: {host}\r\n"
    
    for name, value in headers.items():
        request += f"{name}: {value}\r\n"
    
    request += "\r\n"
    
    result = request.encode()
    if body:
        result += body
    
    return result

