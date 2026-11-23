import socket
from typing import TypedDict


class TCPPacket(TypedDict):
    source_ip: str
    source_port: int
    destination_port: int
    ack: int
    flags: int


class ICMPPacket(TypedDict):
    destination_ip: str
    source_port: int
    destination_port: int


class PacketParser:
    @staticmethod
    def parse_tcp(data: bytes) -> TCPPacket:
        start = (data[0] & 0x0F) * 4 # длина IP-заголовка
        return {
            'source_ip': socket.inet_ntoa(data[12:16]),
            'source_port': int.from_bytes(data[start:start + 2], 'big'),
            'destination_port': int.from_bytes(data[start + 2:start + 4], 'big'),
            'ack': int.from_bytes(data[start + 8:start + 12], 'big'),
            'flags': data[start + 13]
        }

    @staticmethod
    def parse_icmp(data: bytes) -> ICMPPacket | None:
        start = (data[0] & 0x0F) * 4
        if data[start] != 3: # не destination unreachable
            return None

        inner = data[start + 8:] # наш исходный пакет
        inner_start = (inner[0] & 0x0F) * 4
        return {
            'destination_ip': socket.inet_ntoa(inner[16:20]),
            'source_port': int.from_bytes(inner[inner_start:inner_start + 2], 'big'),
            'destination_port': int.from_bytes(inner[inner_start + 2:inner_start + 4], 'big')
        }
