import base64
import cryptography.exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import ec


class Verification:

    def verifysignRSA(self, transaction, signature):

            publikey = serialization.load_pem_public_key(
                self.read(),
                default_backend())

            payload_contents = transaction.read()
            signature = base64.b64decode(signature.read())

            try:
                publikey.verify(
                    signature,
                    payload_contents,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
            except cryptography.exceptions.InvalidSignature as e:
                print('ERROR: Payload and/or signature files failed verification!')

    def verifysignDSA(self, transaction, signature):

            publikeyDSA = serialization.load_pem_public_key(
                self.read(),
                default_backend())

            payload_contents = transaction.read()
            signature = base64.b64decode(signature.read())

            try:
                publikeyDSA.verify(
                    signature,
                    payload_contents,
                    hashes.SHA256(),
                )
            except cryptography.exceptions.InvalidSignature as e:
                print('ERROR: Payload and/or signature files failed verification!')

    def verifysignECDSA(self, transaction, signature):

            publikeyECDSA = serialization.load_pem_public_key(
                self.read(),
                default_backend())

            payload_contents = transaction.read()
            signature = base64.b64decode(signature.read())

            try:
                publikeyECDSA.verify(
                    signature,
                    payload_contents,
                    ec.ECDSA(hashes.SHA256()),
                )
            except cryptography.exceptions.InvalidSignature as e:
                print('ERROR: Payload and/or signature files failed verification!')