#!/usr/bin/python3 -I
"""One bounded HTTP proxy connection, spawned by QEMU guestfwd.

Only public IPv4 TCP 80/443. Resolve once, validate every answer, then connect
to the checked numeric address. This is egress containment, not an exfiltration
filter. No TLS interception and no host credentials.
"""
import ipaddress
import os
import select
import socket
import sys
import time
from urllib.parse import urlsplit


def public_addresses(host, port, resolver=socket.getaddrinfo):
    if port not in (80, 443):
        raise ValueError('only web ports are permitted')
    if not host or len(host) > 253 or any(c in host for c in '\r\n\x00 /\\'):
        raise ValueError('invalid hostname')
    if host.lower().rstrip('.').endswith(('.localhost', '.local', '.internal')):
        raise ValueError('local name denied')
    answers = resolver(host, port, socket.AF_INET, socket.SOCK_STREAM)
    addresses = list(dict.fromkeys(a[4][0] for a in answers))
    # Mixed public/private answers fail closed too, including DNS rebinding.
    ips = [ipaddress.ip_address(a) for a in addresses]
    if not ips or any(not a.is_global or a.is_multicast or a.is_reserved for a in ips):
        raise ValueError('non-public destination denied')
    return addresses


def request(header):
    lines = header.decode('ascii').split('\r\n')
    method, target, version = lines[0].split(' ')
    if version not in ('HTTP/1.0', 'HTTP/1.1'):
        raise ValueError('invalid HTTP version')
    if method == 'CONNECT':
        host, port = target.rsplit(':', 1)
        return host, int(port), None
    if method not in ('GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'):
        raise ValueError('unsupported method')
    url = urlsplit(target)
    if url.scheme != 'http' or url.username or url.password or url.fragment:
        raise ValueError('expected an absolute HTTP URL')
    host, port = url.hostname, url.port or 80
    path = url.path or '/'
    if url.query:
        path += '?' + url.query
    # A new connection is required for each HTTP request. Never forward host
    # supplied proxy authorization, connection overrides or a mismatched Host.
    headers = []
    for line in lines[1:]:
        if not line:
            continue
        name, value = line.split(':', 1)
        if name.lower() not in ('host', 'connection', 'proxy-connection', 'proxy-authorization'):
            headers.append(name + ':' + value)
    out = [f'{method} {path} HTTP/1.1', f'Host: {host}:{port}', 'Connection: close', *headers, '', '']
    return host, port, '\r\n'.join(out).encode('ascii')


def serve():
    deadline = time.monotonic() + 15
    header = bytearray()
    while not header.endswith(b'\r\n\r\n'):
        if len(header) >= 16384 or time.monotonic() >= deadline:
            raise ValueError('header limit')
        if not select.select([0], [], [], max(0, deadline - time.monotonic()))[0]:
            raise ValueError('header timeout')
        char = os.read(0, 1)
        if not char:
            return
        header.extend(char)
    host, port, forward = request(header)
    addresses = public_addresses(host, port)
    # The parent provides host interface addresses to prevent access to a host
    # service bound to its public IP as well as the usual private/loopback IPs.
    denied = set(os.environ.get('MOAT_VM_HOST_IPS', '').split(','))
    if any(a in denied for a in addresses):
        raise ValueError('host destination denied')
    with socket.create_connection((addresses[0], port), timeout=10) as remote:
        if forward is None:
            os.write(1, b'HTTP/1.1 200 Connection Established\r\n\r\n')
        else:
            remote.sendall(forward)
        # Bound connection lifetime and idle time; streaming TLS remains opaque.
        end = time.monotonic() + 3600
        sources = [0, remote]
        while time.monotonic() < end:
            ready, _, _ = select.select(sources, [], [], 60)
            if not ready:
                return
            for source in ready:
                data = os.read(0, 65536) if source == 0 else remote.recv(65536)
                if not data:
                    if source == 0:
                        sources.remove(0)
                        remote.shutdown(socket.SHUT_WR)
                        continue
                    return
                if source == 0:
                    remote.sendall(data)
                else:
                    view = memoryview(data)
                    while view:
                        view = view[os.write(1, view):]


if __name__ == '__main__':
    try:
        serve()
    except (OSError, ValueError, UnicodeError) as error:
        print('moat-vm proxy: ' + str(error), file=sys.stderr)
        try:
            os.write(1, b'HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n')
        except OSError:
            pass
