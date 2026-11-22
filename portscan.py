import argparse
import ipaddress

ALL_PORTS = range(1, 65536)


def parse_port(text: str) -> int:
    if not (text.isascii() and text.isdigit()):
        raise ValueError(f'bad port: {text}')
    port = int(text)
    if port < 1 or port > 65535:
        raise ValueError(f'port out of range: {port}')
    return port

def parse_range(text: str) -> range:
    if '-' not in text:
        port = parse_port(text)
        return range(port, port + 1)

    start, end = text.split('-', 1)
    first = parse_port(start)
    last = parse_port(end)
    if first > last:
        raise ValueError(f'bad range: {text}')
    return range(first, last + 1)

def parse_target(text: str) -> tuple[str, set[int]]:
    protocol, _, ports = text.partition('/')
    protocol = protocol.lower()
    if protocol not in ('tcp', 'udp'):
        raise ValueError(f'unknown protocol: {protocol}')

    if ports == '':
        return protocol, set(ALL_PORTS)

    result: set[int] = set()
    for part in ports.split(','):
        result.update(parse_range(part))
    return protocol, result

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog='portscan', description='TCP and UDP port scanner')
    parser.add_argument('--timeout', type=float, default=2, help='response timeout, seconds')
    parser.add_argument('-j', '--num-threads', type=int, default=1, help='not used: scanner works on select')
    parser.add_argument('-v', '--verbose', action='store_true', help='show response time')
    parser.add_argument('-g', '--guess', action='store_true', help='guess application protocol')
    parser.add_argument('ip', metavar='IP_ADDRESS')
    parser.add_argument('targets', nargs='*', metavar='{tcp|udp}[/[PORT|PORT-PORT],...]')
    args = parser.parse_intermixed_args()

    try:
        args.ip = str(ipaddress.IPv4Address(args.ip))
    except ValueError:
        parser.error(f'bad IP address: {args.ip}')
    if args.timeout <= 0:
        parser.error('timeout must be positive')
    if args.num_threads < 1:
        parser.error('number of threads must be positive')

    if len(args.targets) == 0:
        args.targets = ['tcp', 'udp']

    ports: dict[str, set[int]] = {'tcp': set(), 'udp': set()}
    for target in args.targets:
        try:
            protocol, target_ports = parse_target(target)
        except ValueError as e:
            parser.error(str(e))
        ports[protocol].update(target_ports)

    args.ports = {protocol: sorted(ports[protocol]) for protocol in ports}
    return args


args = parse_args()
print(args.ip, args.timeout, args.verbose, args.guess)
for protocol, ports in args.ports.items():
    print(protocol, len(ports), ports[:5], ports[-3:])
