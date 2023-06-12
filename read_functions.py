import json
import logging

from cryptography.hazmat.primitives.serialization import load_pem_private_key

logger = logging.getLogger()
logger.setLevel("INFO")


def read_settings(settings_file: str) -> dict:
    """
    Функция, которая считывает настройки из файла .json
    :settings_file (str): путь к файлу настроек
    returns: директорию с настройками.
    """
    try:
        with open(settings_file) as json_file:
            settings = json.load(json_file)
        logging.info(
            f"Settings was successfully read from file{settings_file}!")
    except OSError as err:
        logging.warning(
            f"Settings was not read from file{settings_file}\n{err}")
    return settings


def byte_read_text(file_name: str) -> bytes:
    """
    Функция, которая считывает текстовый файл в режиме "rb"
    :file_name (str): путь .txt файлу.
    returns: bytes: текст в виде байтов
    """
    try:
        with open(file_name, "rb") as text_file:
            text = text_file.read()
        logging.info(f"Text was successfully read from file {file_name}!")
    except OSError as err:
        logging.warning(f"Text was not read from file {file_name}\n{err}!")
    return text


def read_private_key(private_pem: str):
    """
    Функция, которая считывает закрытый ключ из файла .pem
    :private_pem (str): название .pem файла.
    returns: _type_: закрытый ключ для алгоритма асимметричного кодирования
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
