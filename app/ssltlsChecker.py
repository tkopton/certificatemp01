import socket
import ssl
from datetime import datetime, timezone
import re
import warnings
import logging
import tempfile
import os
import tempfile, os

from constants import ADAPTER_KIND

# suppress deprecation warnings about TLSVersion lookups (selective)
warnings.filterwarnings(
    "ignore",
    category=DeprecationWarning,
    message=r".*TLSVersion.*deprecated.*",
)

DEFAULT_TIMEOUT = 5.0
logger = logging.getLogger(__name__)

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
            # If cert is empty or missing subject/issuer, try to obtain and decode the DER cert
            if not cert or not cert.get('subject') or not cert.get('issuer'):
                try:
                    der = ssock.getpeercert(binary_form=True)
                    if der:
                        try:
                            pem = ssl.DER_cert_to_PEM_cert(der)
                        except Exception:
                            pem = None
                        if pem:
                            try:
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
                                if decoded:
                                    # Merge decoded fields into cert dict (preserve existing keys)
                                    if not cert:
                                        cert = decoded
                                    else:
                                        for k, v in decoded.items():
                                            if not cert.get(k):
                                                cert[k] = v
                            except Exception:
                                pass
                except Exception:
                    pass
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
        logger.error("Invalid endpoint:", e)
        return

    endpoint = result.object(
                        ADAPTER_KIND, "httpsEndpoint_resource_kind", host)

    try:
        info = connect_and_get_cert(host, port)
    except Exception as e:
        logger.debug("Failed to connect and get certificate:", e)
        info = None

    if info:
        cert = info.get('cert') or {}
        cipher = info.get('cipher')
        negotiated_proto = info.get('protocol')

        if negotiated_proto:
            protocolFamily=("SSL" if negotiated_proto.upper().startswith("SSL") else "TLS")
            endpoint.with_property("protocol_family", protocolFamily)
        if cipher:
            if isinstance(cipher, (list, tuple)):
                endpoint.with_property("cipher_suite", cipher[0])
                if len(cipher) > 1 and cipher[1]:
                    endpoint.with_property("cipher_protocol_label", cipher[1])
                if len(cipher) > 2 and cipher[2]:
                    endpoint.with_metric("cypher_bits", cipher[2])
            else:
                logger.debug("Cipher:", cipher)
        
        notafter = cert.get('notAfter')
        # If the dict from getpeercert() didn't include notAfter, attempt fallback decode
        if not notafter:
            try:
                decoded = _try_decode_server_cert_via_get_server_certificate(host, port)
                if decoded and decoded.get('notAfter'):
                    notafter = decoded.get('notAfter')
                    # merge fallback into cert for later fields if empty
                    if isinstance(cert, dict):
                        cert = dict(cert)
                        cert['notAfter'] = notafter
            except Exception:
                pass

        if notafter:
            dt = parse_notafter(notafter)
            days = days_until(dt)
            endpoint.with_property("certificate_expires", notafter)
            if days is not None:
                endpoint.with_metric("remainig_days", days)
            else:
                logger.debug("Days until expiry: unknown (could not parse date)")
        else:
            logger.debug("No certificate 'notAfter' field available.")

        subj = cert.get('subject')
        if subj:
            subj_str = ", ".join("=".join(pair) for rdn in subj for pair in rdn)
            endpoint.with_property("certificate_subject", subj_str)
        
        issuer = cert.get('issuer')
        if issuer:
            issuer_str = ", ".join("=".join(pair) for rdn in issuer for pair in rdn)
            endpoint.with_property("certificate_issuer", issuer_str)
    
        result.add_object(endpoint)

    else:
        logger.debug("Could not retrieve certificate details.")
