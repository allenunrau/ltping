#!/usr/bin/env python3
"""
ltping — Long-Term Ping Monitor
Continuously pings a target and displays rolling statistics
over user-configurable time windows.
"""

import argparse
import collections
import ctypes
import os
import signal
import socket
import struct
import sys
import time
import select


# ─── ANSI colour / style helpers ─────────────────────────────────────────────

class C:
    """ANSI escape sequences. Disabled automatically when stdout is not a TTY."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    # Foregrounds
    WHITE   = "\033[37m"
    CYAN    = "\033[36m"
    GREEN   = "\033[32m"
    YELLOW  = "\033[33m"
    RED     = "\033[31m"
    MAGENTA = "\033[35m"
    BLUE    = "\033[34m"
    # Bright foregrounds
    BWHITE  = "\033[97m"
    BCYAN   = "\033[96m"
    BGREEN  = "\033[92m"
    BYELLOW = "\033[93m"
    BRED    = "\033[91m"
    # Cursor / clear
    UP      = "\033[A"
    CLEAR   = "\033[2K"
    HIDE    = "\033[?25l"
    SHOW    = "\033[?25h"

    @classmethod
    def disable(cls):
        for attr in list(vars(cls)):
            if not attr.startswith('_') and attr != 'disable' and isinstance(getattr(cls, attr), str):
                setattr(cls, attr, "")


# ─── Windows ICMP (iphlpapi.dll) Support ─────────────────────────────────────
# On Windows, socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP) fails with WinError 10043,
# and SOCK_RAW requires Administrator privileges.
# Windows provides the IP Helper API (iphlpapi.dll) which supports ICMP echo
# without requiring administrative elevation.

class IP_OPTION_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Ttl", ctypes.c_ubyte),
        ("Tos", ctypes.c_ubyte),
        ("Flags", ctypes.c_ubyte),
        ("OptionsSize", ctypes.c_ubyte),
        ("OptionsData", ctypes.c_void_p),
    ]


class ICMP_ECHO_REPLY(ctypes.Structure):
    _fields_ = [
        ("Address", ctypes.c_uint32),
        ("Status", ctypes.c_uint32),
        ("RoundTripTime", ctypes.c_uint32),
        ("DataSize", ctypes.c_uint16),
        ("Reserved", ctypes.c_uint16),
        ("Data", ctypes.c_void_p),
        ("Options", IP_OPTION_INFORMATION),
    ]


class SOCKET_ADDRESS(ctypes.Structure):
    _fields_ = [
        ("lpSockaddr", ctypes.c_void_p),
        ("iSockaddrLength", ctypes.c_int),
    ]


class IP_ADAPTER_UNICAST_ADDRESS(ctypes.Structure):
    pass

IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
    ("Length", ctypes.c_ulong),
    ("Flags", ctypes.c_ulong),
    ("Next", ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
    ("Address", SOCKET_ADDRESS),
]


class IP_ADAPTER_ADDRESSES(ctypes.Structure):
    pass

IP_ADAPTER_ADDRESSES._fields_ = [
    ("Length", ctypes.c_ulong),
    ("IfIndex", ctypes.c_ulong),
    ("Next", ctypes.POINTER(IP_ADAPTER_ADDRESSES)),
    ("AdapterName", ctypes.c_char_p),
    ("FirstUnicastAddress", ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
    ("FirstAnycastAddress", ctypes.c_void_p),
    ("FirstMulticastAddress", ctypes.c_void_p),
    ("FirstDnsServerAddress", ctypes.c_void_p),
    ("DnsSuffix", ctypes.c_wchar_p),
    ("Description", ctypes.c_wchar_p),
    ("FriendlyName", ctypes.c_wchar_p),
]


class SOCKADDR_IN(ctypes.Structure):
    _fields_ = [
        ("sin_family", ctypes.c_short),
        ("sin_port", ctypes.c_ushort),
        ("sin_addr", ctypes.c_ubyte * 4),
        ("sin_zero", ctypes.c_char * 8),
    ]


def _init_windows_console():
    """Enable virtual terminal (ANSI) processing on Windows console."""
    if sys.platform != "win32":
        return
    try:
        from ctypes import wintypes
        kernel32 = ctypes.windll.kernel32
        STD_OUTPUT_HANDLE = -11
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        h_out = kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
        if h_out and h_out != wintypes.HANDLE(-1).value and h_out != -1:
            mode = wintypes.DWORD()
            if kernel32.GetConsoleMode(h_out, ctypes.byref(mode)):
                mode.value |= ENABLE_VIRTUAL_TERMINAL_PROCESSING
                kernel32.SetConsoleMode(h_out, mode)
    except Exception:
        pass
    try:
        os.system("")
    except Exception:
        pass


def _get_windows_adapters() -> dict[str, str]:
    """Return a mapping of {adapter_name: ip_address} for Windows network adapters."""
    adapters: dict[str, str] = {}
    if sys.platform != "win32":
        return adapters

    try:
        from ctypes import wintypes
        iphlpapi = ctypes.windll.iphlpapi
        AF_INET = 2
        flags = 0x0002 | 0x0004 | 0x0008  # skip anycast, multicast, dns server

        buflen = wintypes.ULONG(16384)
        buf = ctypes.create_string_buffer(buflen.value)

        ret = iphlpapi.GetAdaptersAddresses(
            AF_INET, flags, None, ctypes.byref(buf), ctypes.byref(buflen)
        )
        if ret == 111:  # ERROR_BUFFER_OVERFLOW
            buf = ctypes.create_string_buffer(buflen.value)
            ret = iphlpapi.GetAdaptersAddresses(
                AF_INET, flags, None, ctypes.byref(buf), ctypes.byref(buflen)
            )

        if ret == 0:
            curr = ctypes.cast(buf, ctypes.POINTER(IP_ADAPTER_ADDRESSES))
            while curr:
                elem = curr.contents
                name = elem.FriendlyName
                desc = elem.Description
                unicast = elem.FirstUnicastAddress
                while unicast:
                    u_elem = unicast.contents
                    if u_elem.Address.lpSockaddr:
                        sockaddr = ctypes.cast(u_elem.Address.lpSockaddr, ctypes.POINTER(SOCKADDR_IN)).contents
                        if sockaddr.sin_family == AF_INET:
                            ip_str = socket.inet_ntoa(bytes(sockaddr.sin_addr))
                            if name:
                                adapters[name] = ip_str
                            if desc and desc not in adapters:
                                adapters[desc] = ip_str
                            break
                    unicast = u_elem.Next
                curr = elem.Next
    except Exception:
        pass

    if not adapters:
        try:
            import subprocess
            out = subprocess.check_output(
                ["powershell", "-NoProfile", "-Command",
                 "Get-NetIPAddress -AddressFamily IPv4 | Select-Object -Property InterfaceAlias,IPAddress | ConvertTo-Csv -NoTypeInformation"],
                text=True, stderr=subprocess.DEVNULL, timeout=2
            )
            for line in out.strip().splitlines()[1:]:
                parts = [p.strip(' "\'') for p in line.split(",")]
                if len(parts) >= 2 and parts[1]:
                    adapters[parts[0]] = parts[1]
        except Exception:
            pass

    return adapters


def resolve_windows_interface(interface: str) -> str:
    """Resolve an interface name or IP string to a valid local IPv4 address on Windows."""
    # 1. Is it already an IPv4 address?
    try:
        socket.inet_aton(interface)
        if interface.count(".") == 3:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                test_sock.bind((interface, 0))
            except OSError as e:
                print(f"\n{C.BRED}Error:{C.RESET} Cannot bind to IP address '{interface}': {e}")
                sys.exit(1)
            finally:
                test_sock.close()
            return interface
    except OSError:
        pass

    # 2. Look up in adapters
    adapters = _get_windows_adapters()
    for name, ip in adapters.items():
        if name.lower() == interface.lower():
            return ip

    # 3. Not found
    print(f"\n{C.BRED}Error:{C.RESET} Network interface '{interface}' not found on this system.")
    if adapters:
        print("  Available interfaces:")
        for name, ip in adapters.items():
            print(f"    • {C.BOLD}{name}{C.RESET} ({ip})")
    sys.exit(1)


class WindowsPinger:
    """ICMP Echo implementation for Windows using iphlpapi.dll."""
    def __init__(self, interface: str | None = None):
        self.handle = None
        self.source_ip = None
        self.source_ip_ulong = 0

        if interface:
            self.source_ip = resolve_windows_interface(interface)
            self.source_ip_ulong = struct.unpack("<I", socket.inet_aton(self.source_ip))[0]

        from ctypes import wintypes
        self.iphlpapi = ctypes.windll.iphlpapi
        self.kernel32 = ctypes.windll.kernel32

        self.icmp_create_file = self.iphlpapi.IcmpCreateFile
        self.icmp_create_file.restype = wintypes.HANDLE
        self.icmp_create_file.argtypes = []

        self.icmp_close_handle = self.iphlpapi.IcmpCloseHandle
        self.icmp_close_handle.restype = wintypes.BOOL
        self.icmp_close_handle.argtypes = [wintypes.HANDLE]

        self.icmp_send_echo = self.iphlpapi.IcmpSendEcho
        self.icmp_send_echo.restype = wintypes.DWORD
        self.icmp_send_echo.argtypes = [
            wintypes.HANDLE,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint16,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
        ]

        self.icmp_send_echo2ex = getattr(self.iphlpapi, "IcmpSendEcho2Ex", None)
        if self.icmp_send_echo2ex:
            self.icmp_send_echo2ex.restype = wintypes.DWORD
            self.icmp_send_echo2ex.argtypes = [
                wintypes.HANDLE,
                wintypes.HANDLE,
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_void_p,
                ctypes.c_uint16,
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.c_uint32,
            ]

        self.handle = self.icmp_create_file()
        if not self.handle or self.handle == -1 or self.handle == wintypes.HANDLE(-1).value:
            self.handle = None
            err = self.kernel32.GetLastError()
            raise OSError(f"IcmpCreateFile failed with error code {err}")

    def close(self):
        if self.handle:
            try:
                self.icmp_close_handle(self.handle)
            except Exception:
                pass
            self.handle = None

    def __del__(self):
        self.close()

    def ping(self, target_ip: str, timeout: float) -> float | None:
        if not self.handle:
            return None

        dest_addr = struct.unpack("<I", socket.inet_aton(target_ip))[0]
        timeout_ms = max(1, int(timeout * 1000))

        payload = b"ltping_echo_data_32_bytes_pad!!"
        req_size = len(payload)
        req_buf = ctypes.create_string_buffer(payload)

        reply_size = ctypes.sizeof(ICMP_ECHO_REPLY) + req_size + 64
        reply_buf = ctypes.create_string_buffer(reply_size)

        sent_at = time.monotonic()
        try:
            if self.source_ip_ulong and self.icmp_send_echo2ex:
                ret = self.icmp_send_echo2ex(
                    self.handle,
                    None,
                    None,
                    None,
                    self.source_ip_ulong,
                    dest_addr,
                    req_buf,
                    req_size,
                    None,
                    reply_buf,
                    reply_size,
                    timeout_ms,
                )
            else:
                ret = self.icmp_send_echo(
                    self.handle,
                    dest_addr,
                    req_buf,
                    req_size,
                    None,
                    reply_buf,
                    reply_size,
                    timeout_ms,
                )
            recv_at = time.monotonic()
        except Exception:
            return None

        if ret == 0:
            return None

        reply = ICMP_ECHO_REPLY.from_buffer(reply_buf)
        if reply.Status != 0:
            return None

        return (recv_at - sent_at) * 1000.0


# ─── ICMP ping implementation (Linux / Unix) ──────────────────────────────────
#
# Uses SOCK_DGRAM + IPPROTO_ICMP — the "ping socket" ABI exposed by Linux.
# No root required.  The kernel:
#   • assigns its own ident and demultiplexes replies to our socket
#   • strips the IPv4 header, so recv() returns the raw ICMP message
#   • echoes back the seq number we chose
#
# If the kernel refuses the socket (ping_group_range is locked down on some
# distros), we print a short, actionable error and exit.

def _checksum(data: bytes) -> int:
    total = 0
    n = len(data)
    for i in range(0, n - 1, 2):
        total += data[i] + (data[i + 1] << 8)
    if n & 1:
        total += data[-1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def _build_echo_request(seq: int) -> bytes:
    """Build an ICMP echo-request packet.  The ident field is ignored by the
    kernel for SOCK_DGRAM ping sockets (it overwrites it), but the header still
    needs to be syntactically valid, so we write 0."""
    payload = b'\x00' * 16
    # type=8 (echo request), code=0, checksum=0 (placeholder), ident=0, seq
    header = struct.pack('!bbHHH', 8, 0, 0, 0, seq)
    packet = header + payload
    chk    = _checksum(packet)
    header = struct.pack('!bbHHH', 8, 0, chk, 0, seq)
    return header + payload


def _bind_interface(sock: socket.socket, interface: str):
    """Bind a socket to a specific network interface name or source IP."""
    is_ip = False
    try:
        socket.inet_aton(interface)
        if interface.count('.') == 3:
            is_ip = True
    except OSError:
        is_ip = False

    if is_ip:
        sock.bind((interface, 0))
    else:
        opt = getattr(socket, 'SO_BINDTODEVICE', 25)
        sock.setsockopt(socket.SOL_SOCKET, opt, interface.encode('utf-8'))


def validate_interface(interface: str):
    """Verify that the interface name or IP can be bound to a socket."""
    if sys.platform == "win32":
        resolve_windows_interface(interface)
        return

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    except OSError:
        # Handled in ping_once
        return

    try:
        _bind_interface(sock, interface)
    except PermissionError as e:
        print(f"\n{C.BRED}Error:{C.RESET} Binding to interface '{interface}' requires elevated privileges: {e}")
        print(f"  Try running with sudo:")
        print(f"    {C.BOLD}sudo python ltping.py ...{C.RESET}")
        sys.exit(1)
    except OSError as e:
        print(f"\n{C.BRED}Error:{C.RESET} Cannot bind to interface '{interface}': {e}")
        sys.exit(1)
    finally:
        sock.close()


def ping_once(target_ip: str, seq: int, timeout: float, interface: str | None = None, pinger: WindowsPinger | None = None) -> float | None:
    """
    Send one ICMP echo request and wait for the reply.
    Returns the round-trip time in milliseconds, or None on timeout / error.
    """
    if sys.platform == "win32":
        if pinger is not None:
            return pinger.ping(target_ip, timeout)
        try:
            temp_pinger = WindowsPinger(interface)
            try:
                return temp_pinger.ping(target_ip, timeout)
            finally:
                temp_pinger.close()
        except Exception:
            return None

    packet = _build_echo_request(seq)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    except OSError as e:
        # Most common cause: /proc/sys/net/ipv4/ping_group_range is "1 0"
        print(f"\n{C.BRED}Error:{C.RESET} Cannot open ICMP ping socket: {e}")
        print(f"\n  This usually means the kernel's ping_group_range is locked down.")
        print(f"  Fix option 1 — allow your user (one-time, survives reboot):")
        print(f"    {C.BOLD}sudo sysctl -w net.ipv4.ping_group_range='0 2147483647'{C.RESET}")
        print(f"  Fix option 2 — run as root this time:")
        print(f"    {C.BOLD}sudo python ltping.py ...{C.RESET}")
        sys.exit(1)

    sock.settimeout(timeout)

    if interface:
        try:
            _bind_interface(sock, interface)
        except OSError:
            sock.close()
            return None

    sent_at = time.monotonic()
    try:
        sock.sendto(packet, (target_ip, 0))
        while True:
            remaining = timeout - (time.monotonic() - sent_at)
            if remaining <= 0:
                return None
            ready = select.select([sock], [], [], remaining)
            if not ready[0]:
                return None
            data, _ = sock.recvfrom(1024)
            # Reply layout (no IP header): type(1) code(1) cksum(2) ident(2) seq(2) ...
            if len(data) < 8:
                continue
            typ   = data[0]
            r_seq = struct.unpack('!H', data[6:8])[0]
            if typ == 0 and r_seq == seq:          # echo reply, matching seq
                return (time.monotonic() - sent_at) * 1000.0
            # Stray packet (shouldn't happen with SOCK_DGRAM, but be safe)
    except socket.timeout:
        return None
    except OSError:
        return None
    finally:
        sock.close()


# ─── Statistics window ───────────────────────────────────────────────────────

class PingRecord:
    __slots__ = ('timestamp', 'rtt')
    def __init__(self, timestamp: float, rtt: float | None):
        self.timestamp = timestamp
        self.rtt       = rtt


class StatsWindow:
    """
    Maintains a sliding window of the last *seconds* seconds of ping records.
    Thread-safe for appending; reads should happen on the same thread as display.
    """
    def __init__(self, duration: float):
        self.duration = duration
        self.records: collections.deque[PingRecord] = collections.deque()

    def append(self, record: PingRecord):
        self.records.append(record)

    def _trim(self, now: float):
        cutoff = now - self.duration
        while self.records and self.records[0].timestamp < cutoff:
            self.records.popleft()

    def stats(self, now: float) -> dict:
        self._trim(now)
        total  = len(self.records)
        rtts   = [r.rtt for r in self.records if r.rtt is not None]
        rcvd   = len(rtts)
        if total == 0:
            return dict(total=0, received=0, loss_pct=100.0,
                        min_rtt=None, max_rtt=None, avg_rtt=None, jitter=None)

        loss_pct = 100.0 * (total - rcvd) / total if total else 100.0

        if rcvd == 0:
            return dict(total=total, received=0, loss_pct=loss_pct,
                        min_rtt=None, max_rtt=None, avg_rtt=None, jitter=None)

        min_rtt  = min(rtts)
        max_rtt  = max(rtts)
        avg_rtt  = sum(rtts) / rcvd

        # Jitter = average of absolute differences between consecutive RTTs
        if rcvd > 1:
            jitter = sum(abs(rtts[i] - rtts[i-1]) for i in range(1, rcvd)) / (rcvd - 1)
        else:
            jitter = 0.0

        return dict(total=total, received=rcvd, loss_pct=loss_pct,
                    min_rtt=min_rtt, max_rtt=max_rtt, avg_rtt=avg_rtt, jitter=jitter)


# ─── Display renderer ────────────────────────────────────────────────────────

def _fmt_ms(val: float | None) -> str:
    if val is None:
        return "---"
    if val < 1.0:
        return f"{val:.2f}"
    if val < 10.0:
        return f"{val:.1f}"
    return f"{val:.0f}"


def _loss_color(pct: float) -> str:
    if pct == 0.0:   return C.BGREEN
    if pct < 10.0:   return C.BYELLOW
    if pct < 50.0:   return C.YELLOW
    return C.BRED


def _rtt_color(val: float | None) -> str:
    if val is None:   return C.DIM + C.WHITE
    if val < 20.0:    return C.BGREEN
    if val < 100.0:   return C.BCYAN
    if val < 300.0:   return C.BYELLOW
    return C.BRED


def _format_row(label: str, s: dict) -> str:
    # Loss colour
    loss_c  = _loss_color(s['loss_pct'])
    loss_s  = f"{s['loss_pct']:.1f}%"

    # RTT colours
    min_c   = _rtt_color(s['min_rtt'])
    max_c   = _rtt_color(s['max_rtt'])
    avg_c   = _rtt_color(s['avg_rtt'])

    # Jitter colour (green if low relative to avg)
    jit_c = C.BGREEN
    if s['jitter'] is not None and s['avg_rtt'] is not None and s['avg_rtt'] > 0:
        ratio = s['jitter'] / s['avg_rtt']
        if ratio > 0.5:  jit_c = C.BRED
        elif ratio > 0.2: jit_c = C.BYELLOW

    return (
        f"{C.BOLD}{C.BYELLOW}{label:>8s}{C.RESET}"
        f"  {C.BWHITE}{s['total']:>5d}{C.RESET}"
        f"  {C.BWHITE}{s['received']:>5d}{C.RESET}"
        f"  {loss_c}{loss_s:>6s}{C.RESET}"
        f"  {min_c}{_fmt_ms(s['min_rtt']) + ' ms':>7s}{C.RESET}"
        f"  {max_c}{_fmt_ms(s['max_rtt']) + ' ms':>7s}{C.RESET}"
        f"  {avg_c}{_fmt_ms(s['avg_rtt']) + ' ms':>7s}{C.RESET}"
        f"  {jit_c}{_fmt_ms(s['jitter']) + ' ms':>7s}{C.RESET}"
    )


def render_display(windows: list[tuple[int, StatsWindow]],
                   target: str,
                   resolved_ip: str,
                   seq: int,
                   last_rtt: float | None,
                   total_sent: int,
                   total_rcvd: int,
                   lifetime_window: StatsWindow | None = None,
                   interface: str | None = None) -> str:
    """Build the full display string to be written to the terminal."""
    now = time.monotonic()
    lines = []

    # ── Header ──
    rtt_str   = f"{C.BGREEN}{_fmt_ms(last_rtt)} ms{C.RESET}" if last_rtt else f"{C.BRED}timeout{C.RESET}"
    iface_str = f"  iface={C.BOLD}{C.BCYAN}{interface}{C.RESET}" if interface else ""
    header    = (f"{C.BOLD}{C.BWHITE}ltping{C.RESET}  "
                 f"{C.DIM}{C.WHITE}{target}{C.RESET}"
                 f"  ({C.DIM}{C.CYAN}{resolved_ip}{C.RESET}{C.DIM}){C.RESET}"
                 f"{iface_str}"
                 f"  seq={C.BOLD}{seq}{C.RESET}"
                 f"  last={rtt_str}")
    lines.append(header)

    # ── Separator ──
    lines.append(f"{C.DIM}{C.CYAN}{'─' * 72}{C.RESET}")

    # ── Column header ──
    lines.append(
        f"{C.BOLD}{C.BYELLOW}{'Window':>8s}{C.RESET}"
        f"  {C.BOLD}{C.BWHITE}{'Sent':>5s}{C.RESET}"
        f"  {C.BOLD}{C.BWHITE}{'Rcvd':>5s}{C.RESET}"
        f"  {C.BOLD}{C.BWHITE}{'Loss':>6s}{C.RESET}"
        f"  {C.BOLD}{C.BCYAN}{'Min':>7s}{C.RESET}"
        f"  {C.BOLD}{C.BCYAN}{'Max':>7s}{C.RESET}"
        f"  {C.BOLD}{C.BCYAN}{'Avg':>7s}{C.RESET}"
        f"  {C.BOLD}{C.MAGENTA}{'Jitter':>7s}{C.RESET}"
    )
    lines.append(f"{C.DIM}{C.WHITE}{'─' * 72}{C.RESET}")

    # ── Per-window rows ──
    for duration, window in windows:
        s = window.stats(now)

        # Window label
        if duration < 60:
            label = f"{duration}s"
        elif duration < 3600:
            label = f"{duration // 60}m"
        else:
            label = f"{duration // 3600}h"

        lines.append(_format_row(label, s))

    # ── Lifetime row ──
    if lifetime_window is not None:
        lines.append(_format_row("Lifetime", lifetime_window.stats(now)))
    else:
        loss_pct = 100.0 * (total_sent - total_rcvd) / total_sent if total_sent else 100.0
        lines.append(_format_row("Lifetime", dict(
            total=total_sent, received=total_rcvd, loss_pct=loss_pct,
            min_rtt=None, max_rtt=None, avg_rtt=None, jitter=None
        )))

    lines.append(f"{C.DIM}{C.CYAN}{'─' * 72}{C.RESET}")
    lines.append(f"{C.DIM}{C.WHITE}Press Ctrl+C to stop.{C.RESET}")

    return "\n".join(lines)


# ─── Main application ────────────────────────────────────────────────────────

def resolve_target(target: str) -> str:
    """Resolve hostname to IPv4 address."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"{C.BRED}Error:{C.RESET} Cannot resolve '{target}'.")
        sys.exit(1)


def parse_window_spec(spec: str) -> int:
    """
    Parse a window like '10s', '5m', '1h' into seconds.
    Plain integers are treated as seconds.
    """
    spec = spec.strip().lower()
    if spec.endswith('s'):
        return int(spec[:-1])
    if spec.endswith('m'):
        return int(spec[:-1]) * 60
    if spec.endswith('h'):
        return int(spec[:-1]) * 3600
    return int(spec)


def main():
    parser = argparse.ArgumentParser(
        prog="ltping",
        description="Long-term ping monitor with rolling statistics windows.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ltping google.com                         # default 10s / 30s / 60s windows
  ltping 8.8.8.8 -I eth0                   # ping via specific network interface
  ltping 8.8.8.8 -w 5s 15s 60s 5m          # custom windows
  ltping example.com -i 0.5                 # ping every 500 ms
  ltping example.com -w 10s 1m 5m 30m 1h   # long-running monitor
        """)

    parser.add_argument("target",
                        help="Hostname or IP address to ping.")
    parser.add_argument("-w", "--windows", nargs="+", default=["10s", "30s", "60s"],
                        help="Time windows (e.g. 10s 30s 60s 5m 1h). Default: 10s 30s 60s")
    parser.add_argument("-i", "--interval", type=float, default=1.0,
                        help="Seconds between pings. Default: 1.0")
    parser.add_argument("-t", "--timeout", type=float, default=2.0,
                        help="Seconds to wait for each reply. Default: 2.0")
    parser.add_argument("-I", "--interface",
                        help="Source network interface name or IP address to ping from.")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable coloured output.")

    args = parser.parse_args()

    # Disable colours if requested or if not a TTY
    if args.no_color or not sys.stdout.isatty():
        C.disable()

    # Enable ANSI escape processing on Windows console
    if sys.platform == "win32":
        _init_windows_console()

    # Validate interval
    if args.interval <= 0:
        print(f"{C.BRED}Error:{C.RESET} Interval must be > 0.")
        sys.exit(1)

    # Validate interface if provided
    if args.interface:
        validate_interface(args.interface)

    # Parse & sort windows
    window_secs = sorted(set(parse_window_spec(w) for w in args.windows))
    if not window_secs or any(w <= 0 for w in window_secs):
        print(f"{C.BRED}Error:{C.RESET} All windows must be > 0.")
        sys.exit(1)

    # Resolve target
    resolved_ip = resolve_target(args.target)
    target_label = args.target if args.target != resolved_ip else resolved_ip

    # Initialize Windows pinger if on Windows
    win_pinger = None
    if sys.platform == "win32":
        try:
            win_pinger = WindowsPinger(args.interface)
        except OSError as e:
            print(f"\n{C.BRED}Error:{C.RESET} Cannot initialize Windows ICMP service: {e}")
            sys.exit(1)

    # Build StatsWindow objects
    windows: list[tuple[int, StatsWindow]] = [(s, StatsWindow(s)) for s in window_secs]
    lifetime_window = StatsWindow(float('inf'))

    # Graceful shutdown flag
    running = True

    def signal_handler(sig, frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Hide cursor
    sys.stdout.write(C.HIDE)
    sys.stdout.flush()

    seq         = 0
    total_sent  = 0
    total_rcvd  = 0
    last_rtt    = None
    num_lines   = 0  # lines written last frame (for cursor-up erasure)

    # Print initial frame immediately
    output = render_display(windows, target_label, resolved_ip, seq, None, 0, 0, lifetime_window, args.interface)
    num_lines = output.count("\n") + 1
    sys.stdout.write(output + "\n")
    sys.stdout.flush()

    try:
        while running:
            loop_start = time.monotonic()

            # ── Ping ──
            seq += 1
            rtt = ping_once(resolved_ip, seq, args.timeout, args.interface, pinger=win_pinger)
            total_sent += 1
            if rtt is not None:
                total_rcvd += 1
            last_rtt = rtt

            # ── Record into every window ──
            record = PingRecord(time.monotonic(), rtt)
            for _, w in windows:
                w.append(record)
            lifetime_window.append(record)

            # ── Erase previous frame ──
            for _ in range(num_lines):
                sys.stdout.write(C.UP + C.CLEAR)

            # ── Render new frame ──
            output   = render_display(windows, target_label, resolved_ip, seq, last_rtt, total_sent, total_rcvd, lifetime_window, args.interface)
            num_lines = output.count("\n") + 1
            sys.stdout.write(output + "\n")
            sys.stdout.flush()

            # ── Sleep for remainder of interval ──
            elapsed = time.monotonic() - loop_start
            sleep_time = args.interval - elapsed
            if sleep_time > 0:
                # Sleep in small increments so we can react to Ctrl+C quickly
                deadline = time.monotonic() + sleep_time
                while running and time.monotonic() < deadline:
                    time.sleep(min(0.05, deadline - time.monotonic()))

    except (Exception, KeyboardInterrupt):
        pass  # clean exit on any unexpected error during shutdown
    finally:
        if win_pinger:
            win_pinger.close()
        # Show cursor
        sys.stdout.write(C.SHOW)
        sys.stdout.flush()

        # Print final summary
        print()
        print(f"{C.BOLD}{C.BWHITE}─── Summary ───{C.RESET}")
        print(f"  Target : {target_label} ({resolved_ip})")
        if args.interface:
            print(f"  Iface  : {args.interface}")
        print(f"  Sent   : {total_sent}")
        print(f"  Rcvd   : {total_rcvd}")
        if total_sent:
            loss = 100.0 * (total_sent - total_rcvd) / total_sent
            print(f"  Loss   : {_loss_color(loss)}{loss:.1f}%{C.RESET}")
        print()


if __name__ == "__main__":
    main()
