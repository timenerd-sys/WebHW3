import random
import select
import socket
import time


class Guesser:
    def __init__(self, ip: str, timeout: float):
        self.ip: str = ip
        self.timeout: float = timeout
        self.dns_id: bytes = random.randint(0, 65535).to_bytes(2, 'big')

    def http_request(self) -> bytes:
        return (
            b'GET / HTTP/1.1\r\n'
            b'Host: ' + self.ip.encode() + b'\r\n'
            b'Connection: close\r\n'
            b'\r\n'
        )

    def dns_query(self) -> bytes:
        answer = b''
        answer += self.dns_id
        answer += b'\x01\x00' # флаги: RD
        answer += b'\x00\x01' # один вопрос
        answer += b'\x00\x00'
        answer += b'\x00\x00'
        answer += b'\x00\x00'
        answer += b'\x07example\x03com\x00'
        answer += b'\x00\x01' # A
        answer += b'\x00\x01' # IN
        return answer

    def detect(self, request: bytes, response: bytes) -> str:
        if len(response) == 0:
            return '-'
        if response == request:
            return 'ECHO'
        if response.startswith(b'HTTP/'):
            return 'HTTP'
        if len(response) >= 12 and response[0:2] == self.dns_id and response[2] & 0x80:
            return 'DNS'
        return '-'

    def receive(self, sock: socket.socket, size: int) -> bytes:
        received = b''
        try:
            while len(received) < size:
                part = sock.recv(size - len(received))
                if not part:
                    break
                received += part
        except OSError:
            pass
        return received

    def ask_tcp(self, port: int, request: bytes) -> bytes:
        try:
            s = socket.create_connection((self.ip, port), timeout=self.timeout)
        except OSError:
            return b''
        try:
            s.sendall(request)
            return self.receive(s, len(request))
        except OSError:
            return b''
        finally:
            s.close()

    def guess_tcp(self, port: int) -> str:
        request = self.http_request()
        protocol = self.detect(request, self.ask_tcp(port, request))
        if protocol == '-':
            query = self.dns_query()
            response = self.ask_tcp(port, len(query).to_bytes(2, 'big') + query)
            protocol = self.detect(query, response[2:])
        return protocol

    def guess_udp(self, ports: list[int]) -> dict[int, str]:
        result = {port: '-' for port in ports}
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            for request in (self.http_request(), self.dns_query()):
                for port in ports:
                    if result[port] == '-':
                        s.sendto(request, (self.ip, port))

                deadline = time.monotonic() + self.timeout
                while time.monotonic() < deadline:
                    ready, _, _ = select.select([s], [], [], deadline - time.monotonic())
                    if len(ready) == 0:
                        break
                    data, address = s.recvfrom(65535)
                    if address[0] == self.ip and result.get(address[1]) == '-':
                        result[address[1]] = self.detect(request, data)
        finally:
            s.close()
        return result
