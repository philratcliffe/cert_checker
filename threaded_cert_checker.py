#!/usr/bin/python3.5

"""
Get SSL certs for the list of hosts provided.


"""


import sys
import socket
import ssl
import threading
import time

from queue import Queue
from pprint import pprint

from x509 import X509

lock = threading.Lock()

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

def do_work(hostname):
    """Connect to the hostname provided, get the cert, and print out some
    cert info.
    """

    addr = (hostname, 443)

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
                    print ("\nSubject: {}".format(x509_cert.subject_as_str))
    except:
        print("error getting cert for ", hostname)

def worker():
    """Take the jobs from the queue and process them."""
    while True:
        item = q.get()
        do_work(item)
        q.task_done()

def get_hostnames_list(filename):
    """Read the hostsnames from a file and return in a list."""
    return open(filename).read().splitlines()

q = Queue()

#
# Kick off some threads to run the worker function.
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
    with lock:
        print ("Queue size ", q.qsize())

q.join() # Block until all items in the queue processed.

print('time:',time.perf_counter() - start)

