import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization


class SigningDSA:

    def signDocumentDSA(self, key_file):

        private_key = serialization.load_pem_private_key(
             key_file.read(),
             password=None,
             backend=default_backend(),
        )

        prehashed = self.read()

        signature = base64.b64encode(
            private_key.sign(
                prehashed,
                hashes.SHA256(),
            )
        )

        with open('signatureDSA.sig', 'wb') as f:
            f.write(signature)

        return signature