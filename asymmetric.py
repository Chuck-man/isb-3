import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import logging
import random

logger = logging.getLogger()
logger.setLevel('INFO')

