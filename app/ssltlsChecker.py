import sys
import socket
import ssl
from datetime import datetime, timezone
import re
import warnings

# suppress deprecation warnings about TLSVersion lookups (selective)
warnings.filterwarnings(
    "ignore",
    category=DeprecationWarning,
    message=r".*TLSVersion.*deprecated.*",
)

DEFAULT_TIMEOUT = 5.0


def parse_endpoint(ep):
    ep = ep.strip()
    # remove scheme if present
    ep = re.sub(r'^[a-zA-Z]+://', '', ep)
    # IPv6 with brackets [::1]:443
    if ep.startswith('['):
        m = re.match(r'^\[([^\]]+)\](?::(\d+))?$', ep)
        if not m:
            raise ValueError("Invalid IPv6 endpoint format")
        host = m.group(1)
        port = int(m.group(2) or 443)
    else:
        if ':' in ep:
            host, port_s = ep.rsplit(':', 1)
            if not port_s.isdigit():
                raise ValueError("Port must be numeric")
            port = int(port_s)
        else:
            host = ep
            port = 443
    return host, port


def connect_and_get_cert(host, port, timeout=DEFAULT_TIMEOUT):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        ssock = ctx.wrap_socket(sock, server_hostname=host)
        try:
            cert = ssock.getpeercert()
            cipher = ssock.cipher()  # (name, protocol, bits)
            proto = ssock.version()   # e.g. 'TLSv1.2'
            return {
                'cert': cert,
                'cipher': cipher,
                'protocol': proto,
            }
        finally:
            try:
                ssock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            ssock.close()
    except Exception:
        sock.close()
        raise


def parse_notafter(notafter_str):
    # Example format: 'Apr 12 23:59:59 2025 GMT'
    try:
        dt = datetime.strptime(notafter_str, '%b %d %H:%M:%S %Y %Z')
    except Exception:
        # fallback attempt without timezone token
        try:
            dt = datetime.strptime(notafter_str, '%b %d %H:%M:%S %Y')
        except Exception:
            return None
    return dt.replace(tzinfo=timezone.utc)


def days_until(dt):
    if dt is None:
        return None
    now = datetime.now(timezone.utc)
    delta = dt - now
    return max(delta.days, 0)


def _try_decode_server_cert_via_get_server_certificate(host, port):
    """
    Fallback: use ssl.get_server_certificate to obtain a PEM certificate and attempt
    to decode it using the internal helper. Returns a dict like getpeercert().
    This is a best-effort fallback and may not be available on all Python builds.
    """
    try:
        pem = ssl.get_server_certificate((host, port))
    except Exception:
        return None

    # Try to use the internal test decoder (works on CPython).
    try:
        import tempfile
        import os
        tf = tempfile.NamedTemporaryFile(delete=False)
        try:
            tf.write(pem.encode('ascii'))
            tf.flush()
            tf.close()
            try:
                decoded = ssl._ssl._test_decode_cert(tf.name)
            except Exception:
                decoded = None
        finally:
            try:
                os.unlink(tf.name)
            except Exception:
                pass
        return decoded
    except Exception:
        return None


def process_endpoint(result, httpsEndpoint):
    try:
        host, port = parse_endpoint(httpsEndpoint)
    except Exception as e:
        print("Invalid endpoint:", e)
        return

    print(f"Checking {host}:{port} ...")

    try:
        info = connect_and_get_cert(host, port)
    except Exception as e:
        print("Failed to connect and get certificate:", e)
        info = None

    if info:
        cert = info.get('cert') or {}
        cipher = info.get('cipher')
        negotiated_proto = info.get('protocol')

        print()
        print("Negotiated protocol:", negotiated_proto or "unknown")
        if negotiated_proto:
            print("Protocol family:", "SSL" if negotiated_proto.upper().startswith("SSL") else "TLS")
        if cipher:
            if isinstance(cipher, (list, tuple)):
                print("Cipher suite:", cipher[0])
                if len(cipher) > 1 and cipher[1]:
                    print("Cipher protocol label:", cipher[1])
                if len(cipher) > 2 and cipher[2]:
                    print("Cipher bits:", cipher[2])
            else:
                print("Cipher:", cipher)

        notafter = cert.get('notAfter')
        if notafter:
            dt = parse_notafter(notafter)
            days = days_until(dt)
            print()
            print("Certificate expires:", notafter)
            if days is not None:
                print("Days until expiry:", days)
            else:
                print("Days until expiry: unknown (could not parse date)")
        else:
            print()
            print("No certificate 'notAfter' field available.")

        subj = cert.get('subject')
        if subj:
            subj_str = ", ".join("=".join(pair) for rdn in subj for pair in rdn)
            print("Certificate subject:", subj_str)
        issuer = cert.get('issuer')
        if issuer:
            issuer_str = ", ".join("=".join(pair) for rdn in issuer for pair in rdn)
            print("Certificate issuer:", issuer_str)
    else:
        print()
        print("Could not retrieve certificate details.")
