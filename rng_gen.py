#!/usr/bin/env python3
# coding: utf-8
import os
import ssl
import time
import fcntl
import signal
import select
import socket
import struct
import logging

uname = "yourusername"
passwd = "yourpassword"

chunk_size = 768
chunk_header = struct.pack("ii", chunk_size, chunk_size)

exit_ = []


def handler(_, __):
    exit_.append(True)
    logging.info("exiting...")


def recv_at_least(sock, num):
    data = b''
    while len(data) < num:
        data += sock.recv(1024*4)
    return data


def gen_socket():
    logging.debug("logging in...")
    sr = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sr.connect(("qrng.physik.hu-berlin.de", 4499))
    # I didn't put in the effort to check for correct server responses.
    # So far it always failed somewhere if something went wrong either way.
    recv_at_least(sr, 1)
    sr.send(b'AUTH TLS\r\n')
    recv_at_least(sr, 1)
    ctx = ssl.create_default_context()
    # whatever cert the server sends us here seems to not be verifiable the proper way
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sl = ctx.wrap_socket(sr)
    cert = sl.getpeercert(True)
    # insufficient cert check but better than nothing
    if os.path.isfile("qrng.der"):
        with open("qrng.der", "rb") as fc:
            if fc.read() != cert:
                logging.error("invalid server certificate")
                exit()
    else:
        logging.debug("writing new server certificate")
        with open("qrng.der", "wb") as fc:
            fc.write(cert)
    sl.send(f'USER {uname}\r\n'.encode())
    recv_at_least(sl, 1)
    sl.send(f'PASS {passwd}\r\n'.encode())
    recv_at_least(sl, 1)
    logging.info("logged in")
    return sl


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG,
                        format="\r[%(asctime)s.%(msecs)03d][%(levelname)s] %(message)s",
                        datefmt="%Y-%m-%d %H:%M:%S")
    signal.signal(signal.SIGINT, handler)
    s = gen_socket()
    with open("/dev/random", "wb") as fr:
        while not exit_:
            if not select.select([], [fr], [], 1)[1]:
                continue
            logging.debug('/dev/random available for writing')
            try:
                s.send(f'SITE GETDATA {chunk_size}\r\n'.encode())
            except (socket.error, BrokenPipeError):
                if not exit_:
                    logging.warning("disconnected, logging in in 10 seconds...")
                    time.sleep(10)
                    s = gen_socket()
                continue
            rdata = s.recv(chunk_size)
            if len(rdata) != chunk_size:
                logging.warning(f"invalid random data '{rdata[:64]}'")
                continue
            try:
                fcntl.ioctl(fr, 0x40085203, chunk_header + rdata)
                logging.debug(f"{chunk_size} bytes of entropy added")
            except ValueError:
                logging.exception("entropy writing failed")
                time.sleep(10)
    try:
        s.send(b"QUIT\r\n")
    except socket.error:
        pass
