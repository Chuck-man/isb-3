import argparse

from asymmetric import (asymmetric_key_decryption, asymmetric_key_encryption,
                        asymmetric_keys_generation)
from read_functions import (byte_read_text, read_private_key, read_settings,)
from symmetric import (symmetric_key_generation,
                       symmetric_decryption, symmetric_encryption)
from write_functions import (byte_write_text, write_private_key)

SETTINGS_FILE = "files/settings.json"

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-set", "--settings", type=str, default=SETTINGS_FILE, help="Позволяет использовать собственный json-файл с указанием "
                        "необходимых настроек"
                        "(Введите путь к файлу)")
    parser.add_argument("-gen", "--generation",
                       help="Запускает режим генерации ключей", action="store_true")
    parser.add_argument("-enc", "--encryption",
                       help="Запускает режим шифрования", action="store_true")
    parser.add_argument("-dec", "--decryption",
                       help="Запускает режим дешифрования", action="store_true")
    args = parser.parse_args()
    settings = read_settings(args.settings)
    if args.generation:
        private_key, public_key = asymmetric_keys_generation()
        symmetric_key = symmetric_key_generation()
        write_private_key(private_key, settings["private_key"])
        encrypted_symmetric_key = asymmetric_key_encryption(
            public_key, symmetric_key)
        byte_write_text(encrypted_symmetric_key, settings["symmetric_key"])
    elif args.encryption:
        symmetric_key = asymmetric_key_decryption(read_private_key(
            settings["private_key"]), byte_read_text(settings["symmetric_key"]))
        text = byte_read_text(settings["text_file"])
        cipher_text = symmetric_encryption(symmetric_key, text)
        byte_write_text(cipher_text, settings["encrypted_file"])
    elif args.decryption:
        symmetric_key = asymmetric_key_decryption(read_private_key(
            settings["private_key"]), byte_read_text(settings["symmetric_key"]))
        text = symmetric_decryption(
            symmetric_key, byte_read_text(settings["encrypted_file"]))
        byte_write_text(text, settings["decrypted_file"])
