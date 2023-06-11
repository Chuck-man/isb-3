import logging
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key

logger = logging.getLogger()
logger.setLevel('INFO')

def load_settings(settings_file: str) -> dict:
    settings = None
    try:
        with open(settings_file) as json_file:
            settings = json.load(json_file)
        logging.info(f' Настройки считаны из файла {settings_file}')
    except OSError as err:
        logging.warning(f' Ошибка при чтении настроек из файла {settings_file}\n{err}')
    return settings

def save_symmetric_key(key: bytes, file_name: str) -> None:
    try:
        with open(file_name, 'wb') as key_file:
            key_file.write(key)
        logging.info(f' Симметричный ключ успешно сохранен в файл {file_name}')
    except OSError as err:
        logging.warning(f' Ошибка при сохранении симметричного ключа в файл {file_name}\n{err}')

def save_asymmetric_keys(private_key, public_key, private_pem: str, public_pem: str) -> None:
    try:
        with open(private_pem, 'wb') as private_out:
            private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                        encryption_algorithm=serialization.NoEncryption()))
        logging.info(f' Закрытый ключ успешно сохранен в файл {private_pem}')
    except OSError as err:
        logging.warning(f' Ошибка при сохранении закрытого ключа в файл {private_pem}\n{err}')
    try:
        with open(public_pem, 'wb') as public_out:
            public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                     format=serialization.PublicFormat.SubjectPublicKeyInfo))
        logging.info(f' Открытый ключ успешно сохранен в файл {public_pem}')
    except OSError as err:
        logging.warning(f' Ошибка при сохранении открытого ключа в файл {public_pem}\n{err}')