from base64 import b64encode
from maza.core.exploit.encoders import BaseEncoder
from maza.core.exploit.payloads import Architectures


class Encoder(BaseEncoder):
    __info__ = {
        "name": "Perl Base64 Encoder",
        "description": "Module encodes PERL payload to Base64 format.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
    }

    architecture = Architectures.PERL

    def encode(self, payload):
        encoded_payload = str(b64encode(bytes(payload, "utf-8")), "utf-8")
        return f"use MIME::Base64;eval(decode_base64('{encoded_payload}'));"
