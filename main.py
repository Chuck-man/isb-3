import argparse

from symmetric import gen_symmetric_key, encrypt_symmetric, dencrypt_symmetric
from asymmetric import gen_asymmetric_key, encrypt_asymmetric, decrypt_asymmetric
from system_functions import load_settings, save_asymmetric_keys, save_symmetric_key, load_private_key, load_symmetric_key, read_text, write_text

SETTINGS_FILE = 'settings.json'

