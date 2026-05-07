"""逐网卡确认 scapy/Npcap 是否能真正抓到 TCP 包。"""

import sys
import time
from collections import Counter
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
VENDOR_DIR = BASE_DIR / ".vendor"
if VENDOR_DIR.exists():
    sys.path.insert(0, str(VENDOR_DIR))


def main():
    from scapy.all import AsyncSniffer
    from scapy.arch.windows import get_windows_if_list
    from scapy.layers.inet import IP, TCP

    interfaces = []
    for entry in get_windows_if_list():
        name = entry.get("name") or entry.get("description")
        if not name:
            continue
        ipv4 = [
            addr
            for addr in (entry.get("ips") or [])
            if ":" not in addr
            and not addr.startswith("127.")
            and not addr.startswith("169.254.")
        ]
        if ipv4:
            interfaces.append((name, ipv4))

    if not interfaces:
        print("没有发现可用网卡，退出。")
        return

    print("将在以下网卡上抓 TCP 15 秒：")
    for name, ipv4 in interfaces:
        print(f"  - {name}: {', '.join(ipv4)}")
    print()
    print("现在请到另一台主机执行：nmap <对应 IP>")
    print("或者本机随便 curl/浏览一个 https 站点，也能看到 TCP 流量。")
    print()

    counters = {name: Counter() for name, _ in interfaces}

    def make_handler(name, local_ipv4):
        local_set = set(local_ipv4)

        def handler(packet):
            if IP not in packet or TCP not in packet:
                return
            counters[name]["tcp_total"] += 1
            flags = int(packet[TCP].flags)
            src = str(packet[IP].src)
            dst = str(packet[IP].dst)
            if flags & 0x02 and not (flags & 0x10):
                if dst in local_set and src not in local_set:
                    counters[name]["syn_in"] += 1
                else:
                    counters[name]["syn_other"] += 1

        return handler

    sniffers = []
    for name, ipv4 in interfaces:
        sniffer = AsyncSniffer(iface=name, filter="tcp", prn=make_handler(name, ipv4), store=False)
        try:
            sniffer.start()
            sniffers.append((name, sniffer))
        except Exception as exc:
            print(f"[启动失败] {name}: {exc}")

    duration = 15
    for remaining in range(duration, 0, -1):
        time.sleep(1)
        line = " | ".join(
            f"{n}: TCP={c['tcp_total']} SYN_in={c['syn_in']} SYN_other={c['syn_other']}"
            for n, c in counters.items()
        )
        print(f"剩余 {remaining:>2}s  {line}")

    for name, sniffer in sniffers:
        try:
            sniffer.stop()
        except Exception:
            pass

    print()
    print("=== 抓包结果汇总 ===")
    saw_anything = False
    for name, counter in counters.items():
        total = counter["tcp_total"]
        syn_in = counter["syn_in"]
        syn_other = counter["syn_other"]
        if total:
            saw_anything = True
        print(f"  {name}: TCP 包 {total}，入站 SYN {syn_in}，其它 SYN {syn_other}")
    print()
    if not saw_anything:
        print("⚠️ 任何网卡都没有抓到 TCP 包：")
        print("   - 检查是否以管理员权限启动 PowerShell；")
        print("   - 检查 Npcap 安装时是否勾选了 'Support raw 802.11 traffic' 之外的常规选项；")
        print("   - 至少一个网卡应该能看到 TCP 包（哪怕你打开浏览器也行）。")
    else:
        print("✅ Npcap 抓包链路正常。如果 IDS 仍然没告警：")
        print("   - 关注上面 SYN_in（入站 SYN，被本机收到的 SYN 包）那一列；")
        print("   - 如果对应被扫 IP 的网卡 SYN_in > 0，则告警链路应该会触发；")
        print("   - 如果对应网卡 SYN_in = 0，多半是 nmap 流量没真正打到这张网卡。")


if __name__ == "__main__":
    main()
