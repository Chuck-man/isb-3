import logging

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

logger = logging.getLogger()
logger.setLevel("INFO")


def asymmetric_keys_generation() -> tuple:
    """
    Функция генерирует ключи для асимметричного шифрования
    :return: закрытый ключ и открытый ключ
    """
    keys = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_key = keys
    public_key = keys.public_key()
    logging.info(f"Asymmetric keys successfully generated!")
    return (private_key, public_key)


def asymmetric_key_encryption(public_key, symmetric_key: bytes) -> bytes:
    """
    Функция производит асимметричное шифрование по открытому ключу
    :param symmetric_key: симметричный ключ для симметричного шифрования
    :param public_key: открытый ключ для асимметричного шифрования
    :return: зашифрованный симметричный ключ
    """
    encrypted_symmetric_key = public_key.encrypt(symmetric_key, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    logging.info("Asymmetric encryption was successful!")
    return encrypted_symmetric_key


def asymmetric_key_decryption(private_key, symmetric_key: bytes) -> bytes:
    """
    Функция расшифровывает асимметрично зашифрованный текст, с помощью закрытого ключа
    :param symmetric_key: симметричный ключ для симметричного шифрования
    :param private_key: закрытый ключ для асимметричного шифрования
    :return: расшифрованный симметричный ключ
    """
    decrypted_symmetric_key = private_key.decrypt(symmetric_key, padding.OAEP(mgf=padding.MGF1(
        algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    logging.info("Asymmetric decryption was successful!")
    return decrypted_symmetric_key
