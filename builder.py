import socket

SYN = 0x02
RST = 0x04
ACK = 0x10


class Builder:
    def __init__(self, source_ip: str, destination_ip: str, source_port: int):
        self.source_ip: bytes = socket.inet_aton(source_ip)
        self.destination_ip: bytes = socket.inet_aton(destination_ip)
        self.source_port: int = source_port

    def build_tcp(self, port: int, seq: int, flags: int) -> bytes:
        header = self.add_header(port, seq, flags, 0)
        checksum = self.checksum(self.add_pseudo_header(len(header)) + header)
        return self.add_header(port, seq, flags, checksum)

    def add_header(self, port: int, seq: int, flags: int, checksum: int) -> bytes:
        answer = b''
        answer += self.source_port.to_bytes(2, 'big')
        answer += port.to_bytes(2, 'big')
        answer += seq.to_bytes(4, 'big')
        answer += b'\x00\x00\x00\x00' # ack
        answer += bytes([5 << 4, flags])
        answer += (1024).to_bytes(2, 'big') # окно
        answer += checksum.to_bytes(2, 'big')
        answer += b'\x00\x00' # urgent pointer
        return answer

    def add_pseudo_header(self, length: int) -> bytes:
        answer = b''
        answer += self.source_ip
        answer += self.destination_ip
        answer += b'\x00'
        answer += bytes([socket.IPPROTO_TCP])
        answer += length.to_bytes(2, 'big')
        return answer

    @staticmethod
    def checksum(data: bytes) -> int:
        total = 0
        for i in range(0, len(data), 2):
            total += int.from_bytes(data[i:i + 2], 'big')

        while total > 0xFFFF:
            total = (total & 0xFFFF) + (total >> 16)
        return ~total & 0xFFFF
