#! /usr/bin/python3.5

"""
Copyright © 2017 Phil Ratcliffe

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

"""

Prints out certificate information for the server provided.

"""


import sys
import socket
import ssl
from x509 import X509

from pprint import pprint


def create_context(sock, certfile=None):
    """Create an SSL context"""

    # We want to get the cert, so let's be flexible on the protocol.
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)

    # We want a cert from the server.
    context.verify_mode = ssl.CERT_REQUIRED

    # Tries to load a set of default CA certs. Can fail silently.
    context.set_default_verify_paths()

    # If we are using client SSL authentication.
    if certfile:
        context.load_cert_chain(certfile)

    return context


def main(argv):
    """Handles command line arguments and ties everything together"""

    if len(argv) < 2:
        sys.exit('Usage: %s hostname [port]' % sys.argv[0])

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

            print("PEM encoded certificate:")
            print(pem)
            print ("\n\tSubject: \t{}".format(x509_cert.subject_as_str))
            print ("\tCN: \t\t{}".format(x509_cert.cn.decode('utf-8')))
            print ("\tSignature Alg: \t{}".format(x509_cert.get_signature_alg()))
            print ("\tPubKeyAlg: \t{}".format(x509_cert.get_pubkey_alg()))
            print ("\tKey Size: \t{} bits".format(x509_cert.get_key_size()))
            print ("\tNotAfter: \t{} GMT".format(x509_cert.get_not_after_str()))
            print ("\tHasExpired: \t{}".format("Yes" if x509_cert.has_expired() else "No"))
            print ("\tExpires in: \t{} days\n".format(x509_cert.get_days_to_expiry()))

            try:
                ssl.match_hostname(cert, hostname)
            except ssl.CertificateError as ce:
                print ("Certificate error {}\n".format(str(ce)))

            pprint(cert)


if __name__ == '__main__':
    main(sys.argv)
