#!/usr/bin/env python
# https://github.com/alanhuang122/ocsp-utils
import binascii
import idna
import requests
import socket
import sys

from cryptography import x509 as crypto509
from OpenSSL import SSL, crypto
from asn1crypto import core, ocsp, x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import ExtensionOID, ExtensionNotFound
from ocspbuilder import OCSPRequestBuilder
from oscrypto import asymmetric

tlsv1 = SSL.Context(SSL.TLSv1_METHOD)
tlsv11 = SSL.Context(SSL.TLSv1_1_METHOD)
tlsv12 = SSL.Context(SSL.TLSv1_2_METHOD)

contexts = [tlsv12, tlsv11, tlsv1]


def ocsp_lookup(name):
    try:
        encoded_name = idna.encode(name)
        response = get_response(encoded_name)
        return response
    except Exception:
        return {'status': 'failed'}


def get_certs(hostname):
    """Get certs in OpenSSL.crypto.x509 format."""
    for context in contexts:
        try:
            s = socket.socket()
            conn = SSL.Connection(context, s)
            conn.set_connect_state()
            conn.set_tlsext_host_name(hostname)  # SNI
            conn.connect((hostname, 443))
            conn.do_handshake()
            chain = conn.get_peer_cert_chain()
            return chain
        except Exception:
            continue


def convert_to_oscrypto(chain):
    """Converts a list of certs from OpenSSL.crypto.x509 to oscrypto._openssl.asymmetric.Certificate"""
    l = []
    for c in chain:
        l.append(asymmetric.load_certificate(crypto.dump_certificate(crypto.FILETYPE_PEM, c)))
    return l


def create_ocsp_request(cert, issuer):
    """Takes a certificate and the issuing certificate in oscrypto._openssl.asymmetric.Certificate format and creates
    an OCSP request body. """
    builder = OCSPRequestBuilder(cert, issuer)
    return builder.build().dump()


def get_ocsp_uri(hostname):
    """Gets the OCSP responder URL for a website."""
    chain = get_certs(hostname)
    return extract_ocsp_uri(chain[0])


def extract_ocsp_uri(cert: str) -> str:
    """ Parse the leaf certificate and extract the access method and
     access location AUTHORITY_INFORMATION_ACCESS extensions to
     get the ocsp url """

    ocsp_url = ""
    cert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    # Convert to a certificate object in cryptography.io
    certificate = crypto509.load_pem_x509_certificate(
        cert, default_backend()
    )

    # Check to ensure it has an AIA extension
    try:
        aia_extensions = certificate.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        ).value

        # pylint: disable=C0200, W0212
        for index, value in enumerate(aia_extensions):
            if aia_extensions[index].access_method._name == "OCSP":
                ocsp_url = aia_extensions[index].access_location.value

    except ExtensionNotFound:
        raise ValueError(
            "Certificate Authority Information Access (AIA) Extension Missing. Possible MITM Proxy."
        ) from None

    return ocsp_url


def parse_ocsp(response):
    """Converts from asn1crypto.ocsp.OCSPResponse to a dict"""
    OCSP = {}
    OCSP['status'] = response['response_status'].native
    if OCSP['status'] != 'successful':
        print('error')  # .format(OCSP['status']))
        return OCSP
    OCSP['data'] = {}  # ResponseData
    OCSP['data']['version'] = response.response_data['version'].native
    if isinstance(response.response_data['responder_id'].chosen, core.OctetString):
        OCSP['data']['responder_id'] = binascii.hexlify(response.response_data['responder_id'].chosen.native).upper()
    elif isinstance(response.response_data['responder_id'].chosen, x509.Name):
        OCSP['data']['responder_id'] = {'country_name': response.response_data['responder_id'].chosen.native['country_name'],
                                        'organization_name': response.response_data['responder_id'].chosen.native['organization_name'],
                                        'common_name': response.response_data['responder_id'].chosen.native['common_name']}
    OCSP['data']['produced_at'] = response.response_data['produced_at'].native
    OCSP['data']['responses'] = []
    for x in response.response_data['responses'].native:
        respdata = {}
        respdata['cert_id'] = {}
        respdata['cert_id']['hash_algorithm'] = {'algorithm': x['cert_id']['hash_algorithm']
                                                 ['algorithm'], 'parameters': x['cert_id']['hash_algorithm']['parameters']}
        respdata['cert_id']['issuer_name_hash'] = binascii.hexlify(
            response.response_data['responses'].native[0]['cert_id']['issuer_name_hash']).upper()
        respdata['cert_id']['issuer_key_hash'] = binascii.hexlify(
            response.response_data['responses'].native[0]['cert_id']['issuer_key_hash']).upper()
        respdata['cert_id']['serial_number'] = hex(
            response.response_data['responses'].native[0]['cert_id']['serial_number']).upper().replace('X', '')[:-1]
        respdata['cert_status'] = response.response_data['responses'].native[0]['cert_status']
        if not respdata['cert_status']:
            respdata['cert_status'] = 'good'
        # check for revoked
        respdata['this_update'] = response.response_data['responses'].native[0]['this_update']
        respdata['next_update'] = response.response_data['responses'].native[0]['next_update']
        respdata['single_extensions'] = response.response_data['responses'].native[0]['single_extensions']
        OCSP['data']['responses'].append(respdata)
    OCSP['data']['response_extensions'] = response.response_data['response_extensions'].native
    return OCSP


def contact_ocsp_server(certs):
    """Sends an OCSP request to the responding server for a certificate chain"""
    chain = convert_to_oscrypto(certs)
    req = create_ocsp_request(chain[0], chain[1])
    URI = extract_ocsp_uri(certs[0])
    data = requests.post(URI, data=req, stream=True, headers={'Content-Type': 'application/ocsp-request'})
    response = ocsp.OCSPResponse.load(data.raw.data)
    parsed = parse_ocsp(response)
    return parsed


def get_response(hostname):
    """Gets and parses an OCSP response for a hostname"""
    certs = get_certs(hostname)
    parsed = contact_ocsp_server(certs)
    return parsed


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: {} <hostname>".format(sys.argv[0]))
    else:
        print(ocsp_lookup(sys.argv[1]))
