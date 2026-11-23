import random
import select
import socket
import time

from builder import Builder, SYN, RST, ACK
from packet_parser import PacketParser


class TCPScanner:
    def __init__(self, ip: str, timeout: float):
        self.ip: str = ip
        self.timeout: float = timeout
        self.source_port: int = random.randint(40000, 60000)
        self.seq: int = random.randint(0, 0xFFFFFFFF)
        self.builder: Builder = Builder(self.get_source_ip(ip), ip, self.source_port)
        self.sock: socket.socket | None = None

        self.sent: dict[int, float] = {}
        self.result: dict[int, float] = {}

    @staticmethod
    def get_source_ip(ip: str) -> str:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((ip, 80))
            return s.getsockname()[0]
        finally:
            s.close()

    def receive(self) -> None:
        packet = PacketParser.parse_tcp(self.sock.recv(65535))
        if packet['source_ip'] != self.ip or packet['destination_port'] != self.source_port:
            return

        port = packet['source_port']
        if port not in self.sent or packet['ack'] != (self.seq + 1) & 0xFFFFFFFF:
            return

        if packet['flags'] & SYN and packet['flags'] & ACK:
            if port not in self.result:
                self.result[port] = (time.monotonic() - self.sent[port]) * 1000
            self.sock.sendto(self.builder.build_tcp(port, packet['ack'], RST), (self.ip, 0))

    def read_ready(self, timeout: float) -> None:
        ready, _, _ = select.select([self.sock], [], [], timeout)
        while len(ready) > 0:
            self.receive()
            ready, _, _ = select.select([self.sock], [], [], 0)

    def scan(self, ports: list[int]) -> dict[int, float]:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        try:
            for port in ports:
                self.sock.sendto(self.builder.build_tcp(port, self.seq, SYN), (self.ip, 0))
                self.sent[port] = time.monotonic()
                self.read_ready(0)

            deadline = time.monotonic() + self.timeout
            while time.monotonic() < deadline:
                self.read_ready(deadline - time.monotonic())
        finally:
            self.sock.close()
        return self.result
