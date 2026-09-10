#!/usr/bin/python3
from mininet.log import info, debug
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel
from mininet.node import RemoteController
from mininet.link import TCLink

from time import sleep
import argparse
import re


class MyTopo(Topo):

    def __init__(self):
        Topo.__init__(self, sopts={'protocols': 'OpenFlow14', 'switch': 'ovs'})

        h1 = self.addHost('h1', ip='10.1.11.1/24', mac='ea:e9:78:fb:fd:01')
        h2 = self.addHost('h2', ip='10.1.11.2/24', mac='ea:e9:78:fb:fd:02')
        h3 = self.addHost('h3', ip='10.1.11.3/24', mac='ea:e9:78:fb:fd:03')
        h4 = self.addHost('h4', ip='10.1.11.4/24', mac='ea:e9:78:fb:fd:04')
        h5 = self.addHost('h5', ip='10.1.11.5/24', mac='ea:e9:78:fb:fd:05')

        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')

        self.addLink(s1, h1)
        self.addLink(s1, h2)
        self.addLink(s2, h3)
        self.addLink(s3, h4)
        self.addLink(s3, h5)



def run():
    topo = MyTopo()
    controller = RemoteController(name='c0', ip='127.0.0.1', port=6653)
    net = Mininet(topo=topo, controller=controller, link=TCLink)

    info('*** Starting network\n')
    net.start()

    info("[+] Assigning IPv6 addresses\n")
    HOSTS = ["h1", "h2", "h3", "h4", "h5"]
    TEST_SRC = ["h1", "h2"]
    TEST_DST = ["h4", "h5"]

    SRC_IPS, DST_IPS = [], []

    for i, h in enumerate(HOSTS):
        host = net.get(h)
        host.cmd(f'ip a a 2001:db8::{i+1}/64 dev {host.defaultIntf()}')

    for src in TEST_SRC:
        host = net.get(src)
        ipv6_address = host.cmd(
            f"ip -6 a show dev {host.defaultIntf()} | grep inet6 | awk '{{print $2}}'"
        ).strip().splitlines()[0].split('/')[0]
        SRC_IPS.append(ipv6_address)

    for dst in TEST_DST:
        host = net.get(dst)
        ipv6_address = host.cmd(
            f"ip -6 a show dev {host.defaultIntf()} | grep inet6 | awk '{{print $2}}'"
        ).strip().splitlines()[0].split('/')[0]
        DST_IPS.append(ipv6_address)

    info("[+] Waiting for controller to learn topology\n")
    sleep(10)

    info("[1] Initial connectivity test\n")
    for src, src_ip in zip(TEST_SRC, SRC_IPS):
        host = net.get(src)
        for dst, dst_ip in zip(TEST_DST, DST_IPS):
            info(f"[+] {src} → {dst_ip}\n")
            info(host.cmd(f'ping -6 -W 3 -c 3 {dst_ip}'))
            sleep(1)

    info('*** Checking NDP tables\n')
    IS_CORRECT = True
    for src in TEST_SRC:
        host = net.get(src)
        result = host.cmd('ip -6 neigh show')

        info(f' {src} '.center(120, '#') + '\n')
        info(result)
        info(' end '.center(120, '#') + '\n\n')

        for dst, dst_ip in zip(TEST_DST, DST_IPS):

            MAC = None
            for r in result.strip().splitlines():
                r = r.strip()
                if dst_ip in r:
                    dst_host = net.get(dst)
                    MAC = dst_host.MAC()
                    break

            if MAC is None:
                info(f"❌ FAIL: {src} cannot get {MAC} via NDP")
                IS_CORRECT = False
                break

            if 'REACHABLE' not in r and 'STALE' not in r:
                info(f"[+] {r.split(' ')[0]} is not reachable to {src}\n")
                IS_CORRECT = False
                break

            if not MAC == r.split(' ')[-2]:
                info(
                    f"[+] {src} received incorrect mac adress "
                    f"{r.split(' ')[-2]} expected {MAC}\n"
                )
                IS_CORRECT = False
                break

    if not IS_CORRECT:
        info("❌ hosts got incorrect Neighbor Advertisement response\n")
        exit(1)
    info("✅ hosts got correct Neighbor Advertisement response\n")

    # ====== Phase 2: Proxy NDP verification ======
    info("[2] Testing Proxy NDP (flush neighbor cache)\n")
    for src in TEST_SRC:
        net.get(src).cmd('ip -6 neigh flush all')

    # Start tcpdump on destination hosts to detect NDP leakage
    info("[+] Starting tcpdump on destination hosts (h4, h5)\n")
    dump_procs = []
    for dst in TEST_DST:
        h = net.get(dst)
        pcap_path = f"/tmp/{dst}_ndp.pcap"
        h.cmd(f"rm -f {pcap_path}")
        p = h.popen(
            f"tcpdump -n -i {h.defaultIntf()} icmp6 -w {pcap_path}"
        )
        dump_procs.append((h, pcap_path, p))

    sleep(5)

    info("[+] Re-running pings (to trigger Proxy NDP)\n")
    for src, src_ip in zip(TEST_SRC, SRC_IPS):
        host = net.get(src)
        for dst, dst_ip in zip(TEST_DST, DST_IPS):
            info(f"[proxy test] {src} → {dst_ip}\n")
            info(host.cmd(f'ping -6 -W 2 -c 2 {dst_ip}'))

    sleep(3)

    # Stop tcpdump
    info("[+] Stopping tcpdump captures\n")
    for _, _, p in dump_procs:
        p.terminate()
    sleep(5)

    # ====== Analyze packet captures ======
    leakage_detected = False
    for h, pcap_path, _ in dump_procs:
        # info(h.cmd(f"tcpdump -r {pcap_path} 'ip6[40] == 135 or ip6[40] == 136'"))
        count = h.cmd(f"tcpdump -r {pcap_path} 'src net 2001:db8::/64 and ip6[40] == 135 or ip6[40] == 136' 2>/dev/null | wc -l").strip()
        try:
            count = int(count)
        except ValueError:
            count = 0

        if count > 0:
            info(
                f"⚠️  NDP packet leakage detected on {h.name} ({count} packets)\n")
            leakage_detected = True
        else:
            info(f"✅  No NDP packets captured on {h.name}\n")

    net.stop()

    # ====== Final result ======
    info("\n=== Proxy NDP Test Summary ===\n")
    if leakage_detected:
        info("❌ Proxy NDP failed: real hosts received NDP packets.\n")
        exit(1)
    else:
        info("✅ Proxy NDP working: no NDP packets reached destinations.\n")
        exit(0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Check Proxy NDP operation.")
    parser.add_argument("-d", "--debug", action="store_true",
                        help="Enable debug mode")
    args = parser.parse_args()

    setLogLevel('info')
    if args.debug:
        setLogLevel('debug')

    run()
