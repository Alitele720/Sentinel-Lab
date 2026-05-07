"""真实端口扫描抓包入口。"""

import socket
import threading
import uuid
from datetime import datetime, timezone

from .detection import ingest_connection_event
from .storage import connect_db, to_iso, utc_now


def _iter_windows_interface_ipv4():
    """在 Windows 上遍历所有网卡，产出 (网卡名, IPv4 列表)。其它平台返回空。"""
    try:
        from scapy.arch.windows import get_windows_if_list
    except ImportError:
        return

    for entry in get_windows_if_list():
        name = entry.get("name") or entry.get("description")
        if not name:
            continue
        ipv4_addresses = []
        for addr in entry.get("ips", []) or []:
            if ":" in addr:
                continue
            if addr.startswith("169.254."):
                # 链路本地自动配置地址，没有真实路由意义。
                continue
            ipv4_addresses.append(addr)
        if ipv4_addresses:
            yield name, ipv4_addresses


def get_local_ip_addresses():
    """读取本机常见 IPv4 地址，用于过滤真正打到本机的连接。"""
    addresses = {"127.0.0.1"}

    # 优先通过 scapy 枚举所有网卡，避免漏掉非默认路由的接口（VMware/VPN 等）。
    for _name, ipv4_addresses in _iter_windows_interface_ipv4():
        addresses.update(ipv4_addresses)

    try:
        hostname = socket.gethostname()
        for item in socket.getaddrinfo(hostname, None, socket.AF_INET):
            addresses.add(item[4][0])
    except socket.gaierror:
        pass

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("8.8.8.8", 80))
            addresses.add(probe.getsockname()[0])
    except OSError:
        pass
    return addresses


def get_capture_interfaces():
    """在 Windows 上枚举所有带真实 IPv4 的网卡名称，供 sniff() 同时监听。"""
    return [name for name, _addresses in _iter_windows_interface_ipv4()]


def packet_to_connection_event(packet, *, local_ips=None, now=None):
    """把 TCP SYN 包转换成连接事件；非入站探测包返回 None。"""
    try:
        from scapy.layers.inet import IP, TCP
    except ImportError:
        IP = TCP = None

    if IP is None or TCP is None or IP not in packet or TCP not in packet:
        return None

    ip_layer = packet[IP]
    tcp_layer = packet[TCP]
    flags = int(tcp_layer.flags)
    syn_set = bool(flags & 0x02)
    ack_set = bool(flags & 0x10)
    if not syn_set or ack_set:
        return None

    local_ips = local_ips or get_local_ip_addresses()
    source_ip = str(ip_layer.src)
    target_ip = str(ip_layer.dst)
    if target_ip not in local_ips or source_ip in local_ips:
        return None

    timestamp = now
    if timestamp is None:
        timestamp = datetime.fromtimestamp(float(getattr(packet, "time", 0) or 0), timezone.utc)
        if timestamp.timestamp() <= 0:
            timestamp = utc_now()

    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": to_iso(timestamp),
        "source_ip": source_ip,
        "target_ip": target_ip,
        "target_port": int(tcp_layer.dport),
        "protocol": "tcp",
        "result": "attempted",
        "source_kind": "npcap",
    }


class PortscanCaptureThread(threading.Thread):
    """后台抓包线程，捕获发往本机的 TCP SYN 并送入检测链路。"""

    def __init__(self, *, interface="", capture_filter="tcp", stop_event=None):
        super().__init__(daemon=True)
        # 允许通过逗号分隔同时指定多张网卡。
        if interface:
            self.interfaces = [item.strip() for item in interface.split(",") if item.strip()]
        else:
            self.interfaces = []
        self.capture_filter = capture_filter or "tcp"
        self.stop_event = stop_event or threading.Event()
        self.local_ips = get_local_ip_addresses()

    def _resolve_sniff_iface(self):
        """决定 scapy.sniff 的 iface 入参；多网卡 Windows 上要主动列全。"""
        if self.interfaces:
            return self.interfaces[0] if len(self.interfaces) == 1 else list(self.interfaces)
        candidates = get_capture_interfaces()
        if not candidates:
            # Linux 等平台让 scapy 自行决定（通常是 any）。
            return None
        return candidates[0] if len(candidates) == 1 else candidates

    def run(self):
        try:
            from scapy.all import sniff
        except ImportError:
            print("[端口扫描抓包] 未安装 scapy，真实端口扫描检测未启动。")
            return

        iface_arg = self._resolve_sniff_iface()
        if iface_arg is None:
            iface_label = "默认"
        elif isinstance(iface_arg, str):
            iface_label = iface_arg
        else:
            iface_label = ", ".join(iface_arg)
        print(
            f"[端口扫描抓包] 已启动，监听本机地址：{', '.join(sorted(self.local_ips))}；"
            f"网卡：{iface_label}"
        )

        def handle_packet(packet):
            event = packet_to_connection_event(packet, local_ips=self.local_ips)
            if not event:
                return
            conn = connect_db()
            try:
                ingest_connection_event(conn, event)
                conn.commit()
            except Exception as exc:
                conn.rollback()
                print(f"[端口扫描抓包] 处理连接事件失败：{exc}")
            finally:
                conn.close()

        try:
            sniff(
                iface=iface_arg,
                filter=self.capture_filter,
                prn=handle_packet,
                store=False,
                stop_filter=lambda _packet: self.stop_event.is_set(),
            )
        except Exception as exc:
            print(f"[端口扫描抓包] 启动失败：{exc}")


def start_portscan_capture_once(app, runtime):
    """按配置启动一次真实端口扫描抓包线程。"""
    if not app.config.get("PORTSCAN_CAPTURE_ENABLED", False):
        return

    with runtime.portscan_capture_lock:
        thread = runtime.portscan_capture_thread
        if thread is not None and thread.is_alive():
            return
        runtime.portscan_capture_stop_event.clear()
        runtime.portscan_capture_thread = PortscanCaptureThread(
            interface=app.config.get("PORTSCAN_CAPTURE_INTERFACE", ""),
            capture_filter=app.config.get("PORTSCAN_CAPTURE_FILTER", "tcp"),
            stop_event=runtime.portscan_capture_stop_event,
        )
        runtime.portscan_capture_thread.start()
