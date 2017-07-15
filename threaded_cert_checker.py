#!/usr/bin/python3.5

"""
Get SSL certs for the list of hosts provided.


"""


import logging
import socket
import ssl
import sys
import threading
import time

from pprint import pprint
from queue import Queue

from x509 import X509

lock = threading.Lock()


def create_context(sock, verify=True, certfile=None):
    """Create an SSL context"""

    #
    # With the current verstion of the ssl lib can't use
    # PROTOCOL_TLS so using this as provides most interoperability
    # when connectiong to the server.
    #
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)

    if verify:
        # Try to verify the server cert to a trust anchor and fail if can't.
        context.verify_mode = ssl.CERT_REQUIRED
    else:
        #
        # Don't try to verify the server cert. This is the better option if
        # you're only interested in getting the cert and printing its details.
        #
        context.verify_mode = ssl.CERT_NONE

    # Tries to load a set of default CA certs. Can fail silently.
    context.set_default_verify_paths()

    # If we are using client SSL authentication.
    if certfile:
        context.load_cert_chain(certfile)

    return context


def do_work(hostname, port=443):
    """Connect to the hostname provided, get the cert, and print out some
    cert info.
    """

    addr = (hostname, port)

    try:
        with socket.create_connection(addr) as s:
            context = create_context(s)

            #
            # We pass the hostname so that things works correctly if SNI is
            # used at server. Note, not all versions of OpenSSL support SNI
            # so this may fail.
            #
            with context.wrap_socket(s, server_hostname=hostname) as ssl_sock:
                cert = ssl_sock.getpeercert()
                der = ssl_sock.getpeercert(binary_form=True)
                pem = ssl.DER_cert_to_PEM_cert(der)
                x509_cert = X509.from_pem(pem)
                with lock:
                    msg = "Hostname:{}, CN:{}, Expires: {} ({} days)".format(
                        hostname,
                        x509_cert.cn.decode('utf-8'),
                        x509_cert.get_not_after_short_str(),
                        x509_cert.get_days_to_expiry())
                    print(msg)
                    with open('scan_results', 'a') as f:
                        f.write(msg + "\n")
    except socket.gaierror as gaie:
        print("Address-related error connecting to", hostname, gaie)
    except socket.error as se:
        print("Connection related error", hostname, se)


def worker():
    """Take the jobs from the queue and process them."""
    while True:
        item = q.get()
        do_work(item)
        q.task_done()


def get_hostnames_list(filename):
    """Read the hostsnames from a file and return in a list."""
    return open(filename).read().splitlines()

logname="certchecker.log"
logging.basicConfig(filename=logname,
                            filemode='a',
                            format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                            datefmt='%H:%M:%S',
                            level=logging.DEBUG)
logging.info("starting")
q = Queue()

#
# Kick off some threads to run the worker function.
#
for i in range(4):
    t = threading.Thread(target=worker)
    t.daemon = True
    t.start()

hostnames = get_hostnames_list('hosts')
start = time.perf_counter()

#
# Add list hosts to process to the queue.
#
for hostname in hostnames:
    q.put(hostname)

q.join()  # Block until all items in the queue processed.

msg = "time: {:.2f} seconds".format(time.perf_counter() - start)
with open('scan_results', 'a') as f:
                        f.write(msg + "\n")
print(msg)
