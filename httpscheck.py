#!/usr/bin/python

import sys
import socket
import threading
import time

"""
Super simple tool that checks if port 443 is open. This can be used as a
pre-scan to reduce search space before running cert_checker.

Needs to be finsished!!!!

"""

class Scanner(threading.Thread):
    def __init__(self, host, port):
        threading.Thread.__init__(self)
        self.host = host
        self.port = port
        self.status = ""

    def run(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(0)
        try:
            s.connect((self.host, self.port))
        except Exception, e:
            self.status = str(e)
            pass
        try:
            time.sleep(5)
            s.send("")
            s.shutdown(socket.SHUT_RDWR)
            self.status = "port-open"
        except Exception, err:
            #print "port %s is probably closed (no connection after 1 second)" % self.port
            self.status = "port closed"
        finally:
            s.close()

def get_hostnames_list(filename):
    return open(filename).read().splitlines()

if (__name__ == "__main__"):
    hostnames_file = sys.argv[1]
    hosts_list = get_hostnames_list(hostnames_file)
    threads = []
    for host in hosts_list:
        time.sleep(1)
        thread = Scanner(host, 443)
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()
        if thread.status == "port-open":
            print thread.host


