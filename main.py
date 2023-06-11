import argparse

from symmetric import generate_symmetric_key, encrypt_symmetric, decrypt_symmetric
from asymmetric import generate_asymmetric_keys, encrypt_asymmetric, decrypt_asymmetric
from system_functions import load_settings, save_asymmetric_keys, save_symmetric_key, load_private_key, load_symmetric_key, read_text, write_text

SETTINGS_FILE = 'settings.json'

