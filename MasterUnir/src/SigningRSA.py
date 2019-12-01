import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from KeyGen import KeyGen


class SigningRSA:

    def signDocumentRSA(transaction,key_file):

        private_key = serialization.load_pem_private_key(
             key_file.read(),
             password=None,
             backend=default_backend(),
        )

        private_keyHash = KeyGen.getprivatekeyhex();

        prehashed = transaction.read()

        print(private_key.sign)

        signature = base64.b64encode(
            private_key.sign(
                prehashed,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        )

        with open('signatureRSA.sig', 'wb') as f:
            f.write(signature)

        print("private key en hexadecimal: " + private_keyHash.hexdigest())

        return signature;