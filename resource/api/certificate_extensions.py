from asn1crypto.core import SequenceOf, UTF8String


class Roles(SequenceOf):
    _child_spec = UTF8String


def decode(der_bytes: bytes):
    values = Roles.load(der_bytes)
    urls = []
    for i in range(0, len(values)):
        urls.append(values[i].native)
    return urls


def encode(urls: list[str]) -> bytes:
    # Correctly wrap each role in a UTF8String object and create a Roles sequence
    roles_extension = Roles(urls)
    # Dump the Roles sequence to DER format
    return roles_extension.dump()
