#!/usr/bin/env python
import json
import struct
import socket


class MessageSocket:
    def __init__(self, _socket=None):
        if _socket is None:
            _socket = socket.socket()
        self._socket = _socket
        self.buffer = b''

    @classmethod
    def connect(cls, address):
        self = cls()
        self._socket.connect(address)
        return self

    def __enter__(self):
        self._socket.__enter__()
        return self

    def __exit__(self, type, value, traceback):
        self._socket.__exit__(type, value, traceback)

    def close(self):
        self._socket.close()

    def send_data(self, data):
        return self._socket.sendall(data)

    def receive_data(self, size):
        while len(self.buffer) < size:
            packet = self._socket.recv(2**20)
            if not packet:
                raise ConnectionResetError
            self.buffer += packet
        data, self.buffer = self.buffer[:size], self.buffer[size:]
        return data

    def send_message(self, message):
        size = struct.pack('Q', len(message))
        return self.send_data(size + message)

    def receive_message(self):
        size = self.receive_data(8)
        size, = struct.unpack('Q', size)
        return self.receive_data(size)

    def send_json(self, obj):
        return self.send_message(json.dumps(obj).encode())

    def receive_json(self):
        return json.loads(self.receive_message().decode())


class MessageSocketListener:
    def __init__(self, address):
        self._socket = socket.socket()
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind(address)
        self._socket.listen()

    def __enter__(self):
        self._socket.__enter__()
        return self

    def __exit__(self, type, value, traceback):
        self._socket.__exit__(type, value, traceback)

    def close(self):
        self._socket.close()

    def accept(self):
        client, addr = self._socket.accept()
        return MessageSocket(client), addr
