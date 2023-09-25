import symmetric
import asymmetric
import logging
import json

import argparse

SETTINGS_FILE = "files/settings.json"

class HybridAlgorithm:
    def __init__(self, settings_file: str) -> None:
        try:
            with open(settings_file) as json_file:
                self.settings = json.load(json_file)
            logging.info(
                f"Settings was successfully read from file!")
        except OSError as err:
            logging.warning(
                f"Settings was not read from file\n{err}")
            
        self.symmetric = symmetric.SymmetricAlgorithm(self.settings)
        self.asymmetric = asymmetric.AsymmetricAlgorithm(self.settings)

    def keys_generation(self) -> None:
        """
        Генерация и запись симметричного и ассиметричного ключей
        """
        symmetric_key = self.symmetric.symmetric_key_generation()
        private_key, public_key = self.asymmetric.asymmetric_keys_generation()
        encrypted_key = self.asymmetric.symmetric_key_encryption(public_key, symmetric_key)
        self.symmetric.writing_symmetric_key(encrypted_key, self.settings['symmetric_key'])
        self.asymmetric.writing_asymmetric_keys(public_key, self.settings['public_key'], private_key, self.settings['private_key'])
        logging.info('Все ключи были успешно сгенерированы и записаны')

    def encryption(self) -> None:
        """
        Шифрование исходного текста
        """
        private_key = self.asymmetric.reading_private_key(self.settings['private_key'])
        encrypted_key = self.symmetric.reading_symmetric_key(self.settings['symmetric_key'])
        symmetric_key = self.asymmetric.asymmetric_key_decryption(private_key, encrypted_key)
        self.symmetric.symmetric_encryption(symmetric_key, self.settings['text_file'], self.settings['encrypted_file'])

    def decryption(self) -> None:
        """
        Дешифрование зашифрованного текста
        """
        private_key = self.asymmetric.reading_private_key(self.settings['private_key'])
        encrypted_key = self.symmetric.reading_symmetric_key(self.settings['symmetric_key'])
        symmetric_key = self.asymmetric.asymmetric_key_decryption(private_key, encrypted_key)
        self.symmetric.symmetric_decryption(symmetric_key, self.settings['encrypted_file'], self.settings['decrypted_file'])
    
if __name__ == "__main__":
    result = HybridAlgorithm(SETTINGS_FILE)

    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-gen', '--generation', action="store_true", help='Запускает режим генерации ключей')
    group.add_argument('-enc', '--encryption', action="store_true", help='Запускает режим шифрования')
    group.add_argument('-dec', '--decryption', action="store_true", help='Запускает режим дешифрования')
    args = parser.parse_args()

    if args.generation:
        result.keys_generation()
    elif args.encryption:
        result.encryption()
    else:
        result.decryption()

        
