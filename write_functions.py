import logging

from cryptography.hazmat.primitives import serialization

logger = logging.getLogger()
logger.setLevel("INFO")


def byte_write_text(text: bytes, file_name: str) -> None:
    """
    Функция, которая записывает текст в виде байтов
    :text (bytes): текст для записи
    :file_name (str): название .txt файла
    """
    try:
        with open(file_name, "wb") as text_file:
            text_file.write(text)
        logging.info(f"Text was successfully written to file {file_name}!")
    except OSError as err:
        logging.warning(f"Text was not written to file {file_name}\n{err}!")


def write_private_key(private_key, private_pem: str) -> None:
    """
    Функция, которая записывает открытый и закрытый ключи в .pem файлы
    :private_key (_type_): закрытый ключ для алгоритма асимметричного кодирования
    :public_key (_type_): открытый ключ для алгоритма асимметричного кодирования
    :private_pem (str): имя файла .pem для закрытого ключа
    :public_pem (str): имя файла .pem для открытого ключа
    """
    try:
        with open(private_pem, "wb") as private_out:
            private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                        encryption_algorithm=serialization.NoEncryption()))
        logging.info(f"Private key successfully saved to {private_pem}!")
    except OSError as err:
        logging.warning(
            f"Private key was not saved to file {private_pem}\n{err}!")
