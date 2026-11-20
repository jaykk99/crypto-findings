"""HTTP fetches restricted to public destinations (defense in depth).

Production deployments must also deny local/private egress to cover the
DNS-rebinding race between address validation and network connection.
"""
import ipaddress
import socket
import urllib.parse
import urllib.request


def require_public_url(url: str) -> str:
    if not isinstance(url, str):
        raise ValueError('Only http(s) URLs are supported')
    try:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme.lower() not in ('http', 'https'):
            raise ValueError('Only http(s) URLs are supported')
        if not parsed.hostname or parsed.username is not None or parsed.password is not None:
            raise ValueError('Expected a public hostname without credentials')
        port = parsed.port or (443 if parsed.scheme.lower() == 'https' else 80)
        addresses = socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
    except (ValueError, socket.gaierror, UnicodeError) as exc:
        raise ValueError('Invalid or unresolvable HTTP URL: %s' % exc) from exc
    if not addresses:
        raise ValueError('HTTP hostname did not resolve')
    for address in addresses:
        try:
            ip = ipaddress.ip_address(address[4][0])
        except ValueError as exc:
            raise ValueError('Invalid resolved IP') from exc
        if not ip.is_global:
            raise ValueError('URL points to a private or reserved network')
    return url


class SafeRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        require_public_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def public_get(url: str, timeout: int = 20):
    """Open a read-only HTTP response after URL and redirect validation."""
    require_public_url(url)
    request = urllib.request.Request(url, headers={'User-Agent': 'crypto-findings/1.0'})
    return urllib.request.build_opener(SafeRedirects()).open(request, timeout=timeout)
