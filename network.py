from io import BytesIO
from unittest import TestCase

from helper import (
    double_sha256,
    int_to_little_endian,
    little_endian_to_int,
)


NETWORK_MAGIC = b'\xf9\xbe\xb4\xd9'


class NetworkEnvelope:

    def __init__(self, command, payload):
        self.command = command
        self.payload = payload

    def __repr__(self):
        return '{}: {}'.format(
            self.command.decode('ascii'),
            self.payload.hex(),
        )

    @classmethod
    def parse(cls, s):
        '''Takes a stream and creates a NetworkEnvelope'''
        # check the network magic NETWORK_MAGIC
        magic = s.read(4)
        if magic != NETWORK_MAGIC:
            raise RuntimeError('magic is not right')
        # command 12 bytes
        command = s.read(12)
        # payload length 4 bytes, little endian
        payload_length = little_endian_to_int(s.read(4))
        # checksum 4 bytes, first four of double-sha256 of payload
        checksum = s.read(4)
        # payload is of length payload_length
        payload = s.read(payload_length)
        # verify checksum
        calculated_checksum = double_sha256(payload)[:4]
        if calculated_checksum != checksum:
            raise RuntimeError('checksum does not match')
        return cls(command, payload)

    def serialize(self):
        '''Returns the byte serialization of the entire network message'''
        # add the network magic NETWORK_MAGIC
        # command 12 bytes
        # payload length 4 bytes, little endian
        # checksum 4 bytes, first four of double-sha256 of payload
        # payload
        raise NotImplementedError
