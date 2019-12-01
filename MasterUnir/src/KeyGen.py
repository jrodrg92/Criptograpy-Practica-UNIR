from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from HashTool import HashTool


class KeyGen:

    def generateKeyPairsRSA():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )

        # Save the private key to a file.
        with open('private_keyRSA.pem', 'wb') as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        # Save the public key to a file.
        with open('public_keyRSA.pem', 'wb') as f:
            f.write(
                private_key.public_key().public_bytes(
                    encoding = serialization.Encoding.PEM,
                    format = serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )

    def generateKeyPairsDSA():
        private_key = dsa.generate_private_key(
            key_size=2048,
            backend=default_backend(),
        )

        # Save the private key to a file.
        with open('private_keyDSA.pem', 'wb') as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        # Save the public key to a file.
        with open('public_keyDSA.pem', 'wb') as f:
            f.write(
                private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )

    def generateKeyPairsECDSA():
        private_key = ec.generate_private_key(
            ec.SECP256K1(),
            default_backend()
        )

        # Save the private key to a file.
        with open('private_keyECDSA.pem', 'wb') as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        # Save the public key to a file.
        with open('public_keyECDSA.pem', 'wb') as f:
            f.write(
                private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )


    def getprivatekeyhex():

        with open('private_keyRSA.pem', 'r') as f:

            privatekey=f.read()
            return HashTool.hashSha256(str(privatekey[31:-31]))



