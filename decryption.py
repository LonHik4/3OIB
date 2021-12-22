from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as pd
from generation import decryption_key
import pickle


def decryption(setting: dict, iv: bytes):
    """
    Функция дешифрования текста симметричным алгоритмом
    :param setting: dict
    Словарь, содержащий в себе все необходимые файлы
    :param iv: bytes
    Случайное значение для инициализации блочного режима
    :return: None
    """
    with open(setting['symmetric_key'], mode='rb') as key_file:
        key = key_file.read()
    ds_key = decryption_key(setting, key)
    print("Симметричный ключ расшифрован!")
    with open(setting['encrypted_file'], 'rb') as enc_file:
        enc_text = pickle.load(enc_file)
    print("Зашифрованный текст получен!")
    cipher = Cipher(algorithms.TripleDES(ds_key), modes.CBC(iv))
    decrypter = cipher.decryptor()
    dc_text = decrypter.update(enc_text) + decrypter.finalize()
    unpad = pd.ANSIX923(64).unpadder()
    unpadded_dc_text = unpad.update(dc_text) + unpad.finalize()
    res = unpadded_dc_text.decode('UTF-8')
    print("Зашифрованный текст расшифрован!")
    # print("Дешифрованный текст:")
    # print(res)
    with open(setting['decrypted_file'], 'w') as dec_file:
        dec_file.write(res)
