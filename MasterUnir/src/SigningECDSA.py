import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


class SigningECDSA:

    def signDocumentECDSA(self, key_file):
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend(),
        )

        prehashed = self.read()

        signature = base64.b64encode(
            private_key.sign(
                prehashed,
                ec.ECDSA(hashes.SHA256())
            )
        )


        with open('signatureECDSA.sig', 'wb') as f:
            f.write(signature)

        return signature