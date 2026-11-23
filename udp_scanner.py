import select
import socket
import time

from packet_parser import PacketParser


class UDPScanner:
    def __init__(self, ip: str, timeout: float):
        self.ip: str = ip
        self.timeout: float = timeout
        self.udp_sock: socket.socket | None = None
        self.icmp_sock: socket.socket | None = None
        self.source_port: int = 0

        self.closed: set[int] = set()

    def receive(self) -> None:
        packet = PacketParser.parse_icmp(self.icmp_sock.recv(65535))
        if packet is None:
            return
        if packet['destination_ip'] != self.ip or packet['source_port'] != self.source_port:
            return
        self.closed.add(packet['destination_port'])

    def read_ready(self, timeout: float) -> None:
        ready, _, _ = select.select([self.icmp_sock], [], [], timeout)
        while len(ready) > 0:
            self.receive()
            ready, _, _ = select.select([self.icmp_sock], [], [], 0)

    def scan(self, ports: list[int]) -> list[int]:
        self.icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.udp_sock.bind(('', 0))
            self.source_port = self.udp_sock.getsockname()[1]

            for port in ports:
                self.udp_sock.sendto(b'', (self.ip, port))
                self.read_ready(0)

            deadline = time.monotonic() + self.timeout
            while time.monotonic() < deadline:
                self.read_ready(deadline - time.monotonic())
        finally:
            self.udp_sock.close()
            self.icmp_sock.close()
        own_port = self.source_port if self.ip.startswith('127.') else None
        return [port for port in ports if port not in self.closed and port != own_port]
