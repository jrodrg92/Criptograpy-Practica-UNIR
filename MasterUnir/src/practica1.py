import sys

sys.path.append('/home/alastria/PycharmProjects/MasterUnir/src');
from HashTool import HashTool

from KeyGen import KeyGen
from Verification import Verification

from SigningRSA import SigningRSA
from SigningDSA import SigningDSA
from SigningECDSA import SigningECDSA


import cryptography
print(cryptography.__version__)

"""
PARTE 1 

Hash SHA256 en hexadecimal de la frase:
        Estamos aplicando de forma práctica los conocimientos de criptografia"""
myString = "Estamos aplicando de forma práctica los conocimientos de criptografia";
hashString = HashTool.hashSha256(myString)
print(hashString.hexdigest())

"""Hash SHA256 en hexadecimal de la palabra:
        criptografia"""
myString = "criptografia"
hashString = HashTool.hashSha256(myString)
print(hashString.hexdigest())

"""Hash SHA256 en hexadecimal de la palabra: criptografio"""
myString = 'criptografio'
hashString=HashTool.hashSha256(myString)
print(hashString.hexdigest())

"""Hash MD5 en hexadecimal del fichero TransaccionBitcoint.txt:
        criptografio"""
transaction = open('TransaccionBitcoin.txt', 'r')
hashFile = HashTool.hashMd5(transaction)
print(hashFile.hexdigest())


"""
PARTE 2
2.a
generar par de claves ppublica y privada 2048bits exp=65537
Las almacenamos en el fichero generado, se almacenara automaticamente.
"""
KeyGen.generateKeyPairsRSA()

"""
2.c
Firmar el documento
"""
private_keyRSA = open('private_keyRSA.pem', 'rb')
transaction = open('TransaccionBitcoin.txt', 'rb')
sign = SigningRSA.signDocumentRSA(transaction, private_keyRSA)
print(sign)
""" 
2-d
VERIFICAR FIRMA
"""
publickeyRSA = open('public_keyRSA.pem', 'rb')
signatureRSA = open('signatureRSA.sig', 'rb')
Verification.verifysignRSA(publickeyRSA, transaction, signatureRSA)
print('Verificado RSA')

"""
2.e
Firma con DSA, verifica la firma
"""
KeyGen.generateKeyPairsDSA()
private_keyDSA = open('private_keyDSA.pem', 'rb')
sign = SigningDSA.signDocumentDSA(transaction, private_keyDSA)
print(sign)
publickeyDSA = open('public_keyDSA.pem', 'rb')
signatureDSA = open('signatureDSA.sig', 'rb')
Verification.verifysignDSA(publickeyDSA, transaction, signatureDSA)
print('Verificada DSA')

"""
2.f
Firmar con ECDSA , verificar firma
"""
KeyGen.generateKeyPairsECDSA()
private_keyECDSA = open('private_keyECDSA.pem', 'rb')
sign = SigningECDSA.signDocumentECDSA(transaction, private_keyECDSA)
print(sign)
pubkeyECDSA = open('public_keyECDSA.pem', 'rb')
signatureECDSA = open('signatureECDSA.sig', 'rb')
Verification.verifysignECDSA(pubkeyECDSA, transaction, signatureECDSA)
print('Verificado ECDSA')