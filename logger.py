import logging
import os


os.makedirs('logs', exist_ok=True)

logg = logging.getLogger('email_Security')
logg.setLevel(logging.DEBUG)

debug_handler = logging.FileHandler('logs/debug.log')
debug_handler.setLevel(logging.DEBUG)

error_handler = logging.FileHandler('logs/error.log')
error_handler.setLevel(logging.ERROR)

formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
debug_handler.setFormatter(formatter)
error_handler.setFormatter(formatter)

logg.addHandler(debug_handler)
logg.addHandler(error_handler)