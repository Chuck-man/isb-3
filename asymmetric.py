import logging

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import (load_pem_private_key,
                                                          load_pem_public_key)

logger = logging.getLogger()
logger.setLevel("INFO")

"""
def asymmetric_keys_generation() -> tuple:
    
    Функция генерирует ключи для асимметричного шифрования
    :return: закрытый ключ и открытый ключ
    
    keys = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_key = keys
    public_key = keys.public_key()
    logging.info(f"Asymmetric keys successfully generated!")
    return (private_key, public_key)


def asymmetric_key_encryption(public_key, symmetric_key: bytes) -> bytes:
    
    Функция производит асимметричное шифрование по открытому ключу
    :param symmetric_key: симметричный ключ для симметричного шифрования
    :param public_key: открытый ключ для асимметричного шифрования
    :return: зашифрованный симметричный ключ
    
    encrypted_symmetric_key = public_key.encrypt(symmetric_key, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    logging.info("Asymmetric encryption was successful!")
    return encrypted_symmetric_key


def asymmetric_key_decryption(private_key, symmetric_key: bytes) -> bytes:
    
    Функция расшифровывает асимметрично зашифрованный текст, с помощью закрытого ключа
    :param symmetric_key: симметричный ключ для симметричного шифрования
    :param private_key: закрытый ключ для асимметричного шифрования
    :return: расшифрованный симметричный ключ
    
    decrypted_symmetric_key = private_key.decrypt(symmetric_key, padding.OAEP(mgf=padding.MGF1(
        algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    logging.info("Asymmetric decryption was successful!")
    return decrypted_symmetric_key
"""

class AsymmetricAlgorithm:
    def __init__(self, settings: dict) -> None:
        """
        Инициализация симметричного шифрования
        settings (dict): настройки, содержащие пути к файлам
        """
        self.settings = settings
        logging.info('Настройки по умолчанию загружены')
    
    def asymmetric_keys_generation(self) -> tuple:
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


    def symmetric_key_encryption(self, public_key, symmetric_key: bytes) -> bytes:
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


    def asymmetric_key_decryption(self, private_key, symmetric_key: bytes) -> bytes:
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
    
    def writing_asymmetric_keys(self, public_key, public_pem: str, private_key, private_pem: str) -> None:
        """
        Функция, которая записывает ключи в виде байтов
        :public_key (bytes): публичный ключ
        :private_key (bytes): приватный ключ
        :public_pem (str): название файла, в который сохраняется публичный ключ
        :private_pem (str): название файла, в который сохраняется приватный ключ
        """
        
        public_key_serialized = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        private_key_serialized = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        try:
            with open(public_pem, "wb") as text_file:
                text_file.write(public_key_serialized)
            logging.info(f"Public key was successfully written to file {public_pem}!")
        except OSError as err:
            logging.warning(f"Public key was not written to file {public_pem}\n{err}!")

        try:
            with open(private_pem, "wb") as text_file:
                text_file.write(private_key_serialized)
            logging.info(f"Private key was successfully written to file {private_pem}!")
        except OSError as err:
            logging.warning(f"Private key was not written to file {private_pem}\n{err}!")

    def reading_public_key(self, public_pem: str) -> None:
        """
        Функция, которая считывает ключ в режиме "rb"
        :file_name (str): путь .txt файлу.
        returns: bytes: текст в виде байтов
        """
        public_key = None
        try:
            with open(public_pem, "rb") as text_file:
                public_bytes = text_file.read()
            public_key = load_pem_public_key(public_bytes, password=None)
            logging.info(f"Key was successfully read from file {public_pem}!")
        except OSError as err:
            logging.warning(f"Key was not read from file {public_pem}\n{err}!")
        return public_key
    
    def reading_private_key(self, private_pem: str) -> None:
        """
        Функция, которая считывает ключ в режиме "rb"
        :file_name (str): путь .txt файлу.
        returns: bytes: текст в виде байтов
        """
        private_key = None
        try:
            with open(private_pem, "rb") as pem_in:
                private_bytes = pem_in.read()
            private_key = load_pem_private_key(private_bytes, password=None)
            logging.info(f"Private key successfully loaded from {private_pem}!")
        except OSError as err:
            logging.warning(
                f"Private key was not loaded from file {private_pem}\n{err}!")
        return private_key
