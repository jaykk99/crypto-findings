import socket
import urllib.request
from unittest.mock import patch

import pytest

from app.safe_http import SafeRedirects, public_get, require_public_url


def dns_with(address):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (address, 443))]


def test_private_ip_literals_are_blocked():
    for url in ('http://127.0.0.1/a', 'http://169.254.169.254/metadata',
                'http://10.0.0.3/', 'http://[::1]/', 'http://192.168.0.1/'):
        with pytest.raises(ValueError, match='private or reserved'):
            require_public_url(url)


def test_private_dns_answer_is_blocked():
    with patch('socket.getaddrinfo', return_value=dns_with('172.16.0.2')):
        with pytest.raises(ValueError, match='private or reserved'):
            require_public_url('https://internal.example/address')


def test_mixed_dns_answers_fail_closed():
    responses = dns_with('93.184.215.14') + dns_with('127.0.0.1')
    with patch('socket.getaddrinfo', return_value=responses):
        with pytest.raises(ValueError, match='private or reserved'):
            require_public_url('https://example.org/')


def test_http_schemes_and_embedded_credentials():
    with patch('socket.getaddrinfo', return_value=dns_with('93.184.215.14')):
        assert require_public_url('https://example.org/')
    for url in ('file:///etc/passwd', 'ftp://example.org/',
                'http://user:secret@example.org/'):
        with pytest.raises(ValueError):
            require_public_url(url)


def test_private_redirect_target_rejected():
    with pytest.raises(ValueError, match='private or reserved'):
        SafeRedirects().redirect_request(
            urllib.request.Request('https://public.example/'), None,
            302, 'Found', {}, 'http://127.0.0.1/latest')


def test_public_get_uses_guarded_redirect_handler_without_network():
    with patch('socket.getaddrinfo', return_value=dns_with('93.184.215.14')), \
            patch('urllib.request.build_opener') as opener:
        opener.return_value.open.return_value = 'fake-response'
        assert public_get('https://example.org/model', timeout=2) == 'fake-response'
        assert isinstance(opener.call_args.args[0], SafeRedirects)
        assert opener.return_value.open.call_args.kwargs['timeout'] == 2
