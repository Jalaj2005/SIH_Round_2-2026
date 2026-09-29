"""Read-only packet sources.

PcapFileSource - replay a .pcap/.pcapng (dev, tests, benchmarks; pair with tcpreplay
                 onto a veth/tap for live-like tests).
LiveSource     - AF_PACKET raw socket on the diode-facing NIC. Receive only: the
                 class exposes no send path, and the socket is never written to.
                 Run on an RX-only tap/SPAN port; the physical diode is the real
                 guarantee, this is defense in depth.
"""
import socket
import struct
import time

import dpkt


class PcapFileSource:
    def __init__(self, path, speed=0.0):
        """speed=0 -> as fast as possible; 1.0 -> original timing; 10 -> 10x."""
        self.path, self.speed = path, speed
        self.linktype = 1

    def __iter__(self):
        with open(self.path, "rb") as fh:
            try:
                rd = dpkt.pcap.Reader(fh)
            except ValueError:
                fh.seek(0)
                rd = dpkt.pcapng.Reader(fh)
            self.linktype = rd.datalink()
            t0 = w0 = None
            for ts, buf in rd:
                if self.speed > 0:
                    if t0 is None:
                        t0, w0 = ts, time.time()
                    delay = (ts - t0) / self.speed - (time.time() - w0)
                    if delay > 0:
                        time.sleep(delay)
                yield ts, buf


class LiveSource:
    def __init__(self, iface, snaplen=2048, poll_timeout=0.05):
        self.iface, self.snaplen, self.poll_timeout = iface, snaplen, poll_timeout
        self.linktype = 1
        self._sock = None

    def __enter__(self):
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        s.bind((self.iface, 0))
        s.settimeout(self.poll_timeout)
        try:  # big kernel buffer: the only place drops can hide in a passive tap
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 256 * 1024 * 1024)
        except OSError:
            pass
        self._sock = s
        return self

    def __exit__(self, *a):
        if self._sock:
            self._sock.close()

    def __iter__(self):
        recv = self._sock.recv
        n = self.snaplen
        while True:
            try:
                buf = recv(n)
            except socket.timeout:
                yield None, None          # lets the pipeline tick timers when idle
                continue
            yield time.time(), buf
