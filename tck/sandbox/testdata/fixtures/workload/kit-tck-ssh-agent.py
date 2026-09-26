#!/usr/bin/env python3
"""Observes the SSH agent a sandbox was given, one request at a time.

kit-tck-ssh-agent socket                    print SSH_AUTH_SOCK (empty when unset)
kit-tck-ssh-agent list                      print the offered keys, one authorized_keys line each
kit-tck-ssh-agent sign KEY                  sign random bytes: a signature for no protocol
kit-tck-ssh-agent sshsig NAMESPACE KEY      sign a namespaced (SSHSIG) signature
kit-tck-ssh-agent login USER KEY SID [BIND] sign a login for session SID, after the
                                            session binding BIND on the same connection
kit-tck-ssh-agent raw TYPE                  send an empty request of TYPE
kit-tck-ssh-agent extension NAME            send an extension request NAME

KEY is an authorized_keys line; SID and BIND are hex. A signing request
prints "data <hex>" and "signature <hex>" so the suite can verify the
signature itself rather than take this script's word for it.

Exit 0: the agent answered with success. Exit 1: it answered with a
failure. Exit 2: there was no agent to ask. Anything else is a usage or
protocol error, which the suite reports as such.
"""

import base64
import os
import secrets
import socket
import struct
import sys

REQUEST_IDENTITIES = 11
IDENTITIES_ANSWER = 12
SIGN_REQUEST = 13
SIGN_RESPONSE = 14
SUCCESS = 6
FAILURE = 5
EXTENSION = 27
EXTENSION_FAILURE = 28
USERAUTH_REQUEST = 50


def string(b):
    if isinstance(b, str):
        b = b.encode()
    return struct.pack(">I", len(b)) + b


def read_string(buf, off):
    (n,) = struct.unpack_from(">I", buf, off)
    return buf[off + 4 : off + 4 + n], off + 4 + n


class Agent:
    def __init__(self):
        path = os.environ.get("SSH_AUTH_SOCK", "")
        if not path:
            sys.exit(2)
        self.sock = socket.socket(socket.AF_UNIX)
        try:
            self.sock.connect(path)
        except OSError:
            sys.exit(2)

    def call(self, kind, body=b""):
        msg = bytes([kind]) + body
        self.sock.sendall(struct.pack(">I", len(msg)) + msg)
        head = self._read(4)
        (n,) = struct.unpack(">I", head)
        reply = self._read(n)
        return reply[0], reply[1:]

    def _read(self, n):
        out = b""
        while len(out) < n:
            chunk = self.sock.recv(n - len(out))
            if not chunk:
                sys.exit(1)
            out += chunk
        return out


def key_blob(line):
    return base64.b64decode(line.split()[1])


def key_type(line):
    return line.split()[0]


def sign(agent, key, data):
    kind, body = agent.call(SIGN_REQUEST, string(key_blob(key)) + string(data) + struct.pack(">I", 0))
    if kind != SIGN_RESPONSE:
        sys.exit(1)
    signature, _ = read_string(body, 0)
    print("data", data.hex())
    print("signature", signature.hex())
    sys.exit(0)


def sshsig_data(namespace):
    # PROTOCOL.sshsig: the preamble, the namespace, a reserved string, the
    # hash algorithm, and the hash of the message.
    digest = secrets.token_bytes(64)
    return b"SSHSIG" + string(namespace) + string(b"") + string(b"sha512") + string(digest)


def login_data(user, key, sid):
    # RFC 4252 section 7: what a client signs to log in with a public key.
    return (
        string(sid)
        + bytes([USERAUTH_REQUEST])
        + string(user)
        + string(b"ssh-connection")
        + string(b"publickey")
        + b"\x01"
        + string(key_type(key))
        + string(key_blob(key))
    )


def main(argv):
    if not argv:
        sys.exit(64)
    op, args = argv[0], argv[1:]
    if op == "socket":
        print(os.environ.get("SSH_AUTH_SOCK", ""))
        return
    agent = Agent()
    if op == "list":
        kind, body = agent.call(REQUEST_IDENTITIES)
        if kind != IDENTITIES_ANSWER:
            sys.exit(1)
        (count,) = struct.unpack_from(">I", body, 0)
        off = 4
        for _ in range(count):
            blob, off = read_string(body, off)
            _, off = read_string(body, off)
            name, _ = read_string(blob, 0)
            print(name.decode(), base64.b64encode(blob).decode())
        return
    if op == "sign" and len(args) == 1:
        sign(agent, args[0], secrets.token_bytes(32))
    if op == "sshsig" and len(args) == 2:
        sign(agent, args[1], sshsig_data(args[0]))
    if op == "login" and len(args) in (3, 4):
        user, key, sid = args[0], args[1], bytes.fromhex(args[2])
        if len(args) == 4:
            kind, _ = agent.call(EXTENSION, string(b"session-bind@openssh.com") + bytes.fromhex(args[3]))
            # A refused binding is not the end of the observation: the
            # login that follows must be refused too, and that is what
            # the suite judges.
            print("bind", "accepted" if kind == SUCCESS else "refused")
        sign(agent, key, login_data(user, key, sid))
    if op == "raw" and len(args) == 1:
        kind, _ = agent.call(int(args[0]))
        sys.exit(0 if kind == SUCCESS else 1)
    if op == "extension" and len(args) == 1:
        kind, _ = agent.call(EXTENSION, string(args[0]))
        sys.exit(0 if kind == SUCCESS else 1)
    sys.exit(64)


if __name__ == "__main__":
    main(sys.argv[1:])
