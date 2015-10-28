import sys
import socket
import ssl
from x509 import X509

from pprint import pprint


def create_context(sock, certfile=None):
    """Create an SSL context"""

    # We want to get the cert, so let's be flexible on the protocol.
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)

    context.verify_mode = ssl.CERT_REQUIRED

    # Note that this can fail silently
    context.set_default_verify_paths()

    if certfile:
        context.load_cert_chain(certfile)

    return context


def main(argv):
    """Handles command line arguments and ties everything together"""

    hostname = argv[1]
    port = int(argv[2]) if len(argv) > 2 else 443
    addr = (hostname, port)

    with socket.create_connection(addr) as s:
        context = create_context(s)

        # We pass the hostname so that things works correctly if SNI is
        # used at server. Note, that not all versions of OpenSSL support SNI
        # so this may fail.
        with context.wrap_socket(s, server_hostname=hostname) as ssl_sock:

            cert = ssl_sock.getpeercert()
            der = ssl_sock.getpeercert(binary_form=True)
            pem = ssl.DER_cert_to_PEM_cert(der)
            x509_cert = X509.from_pem(pem)

            print ("\nSubject: {}".format(x509_cert.subject_as_str))
            print ("\nCN: {}".format(x509_cert.cn.decode('utf-8')))
            print ("\nPubKeyAlg: {}\n".format(x509_cert.get_pubkey_alg()))

            try:
                ssl.match_hostname(cert, hostname)
            except ssl.CertificateError as ce:
                print ("Certificate error {}\n".format(str(ce)))

            pprint(cert)


if __name__ == '__main__':
    main(sys.argv)
