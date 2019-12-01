import hashlib

class HashTool:

    def hashSha256(string):
        return hashlib.sha256(string.encode());

    def hashMd5(transaction):
        return hashlib.md5(transaction.read().encode());
