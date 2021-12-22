from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as pd
from generation import decryption_key
import pickle


def encryption(setting: dict, iv: bytes):
    """
    Функция шифрования текста симметричным алгоритмом
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
    with open(setting['initial_file'], 'r', encoding='UTF-8') as f:
        res = f.read()
        print("Исходный текст получен!")
    # print("Исходный текст:")
    # print(res)
    pad = pd.ANSIX923(64).padder()
    text = bytes(res, 'UTF-8')
    padded_text = pad.update(text) + pad.finalize()
    cipher = Cipher(algorithms.TripleDES(ds_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    enc_text = encryptor.update(padded_text) + encryptor.finalize()
    print("Исходный текст зашифрован!")
    print("Зашифрованный текст:")
    print(enc_text)
    with open(setting['encrypted_file'], 'wb') as enc_file:
        pickle.dump(enc_text, enc_file)