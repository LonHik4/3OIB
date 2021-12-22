import json
import os
from encryption import encryption
from generation import generation, encryption_sym_key
from decryption import decryption


def set_iv_value(setting: dict) -> None:
    """
    Функция создания случайного значения для инициализации блочного режима
    :param setting: dict
    Словарь, содержащий в себе все необходимые файлы
    :return: None
    """
    tmp = os.urandom(8)
    with open(setting['iv_value'], 'wb') as key_file:
        key_file.write(tmp)


def get_iv_value(setting: dict) -> bytes:
    """
    Функция получения случайного значения для инициализации блочного режима
    :param setting: dict
    Словарь, содержащий в себе все необходимые файлы
    :return: bytes
    Случайное значение для инициализации блочного режима
    """
    with open(setting['iv_value'], "rb") as f:
        result = f.read()
    return result


if __name__ == '__main__':
    settings = {
        'initial_file': 'data.txt',
        'encrypted_file': 'encrypted_file.pickle',
        'decrypted_file': 'decrypted_file.txt',
        'symmetric_key': 'symmetric_key.txt',
        'public_key': 'public_key.pem',
        'private_key': 'private_key.pem',
        'iv_value': 'iv.bin',
    }
    with open('settings.json', 'w') as fp:
        json.dump(settings, fp)
    with open('settings.json') as json_file:
        json_data = json.load(json_file)
    while True:
        print('\n')
        print("1. Зашифровать текст")
        print("2. Дешифровать текст")
        print("3. Сгенерировать ключи")
        print("0. Выйти из программы")
        cmd = input("Выберите действие: ")

        if cmd == "1":
            iv = get_iv_value(settings)
            print("Шифруем...")
            encryption(settings, iv)
            print("Готово!")

        elif cmd == "2":
            iv = get_iv_value(settings)
            print("Дешифруем...")
            decryption(settings, iv)
            print("Готово!")

        elif cmd == "3":
            while True:
                print("1. 64 бит")
                print("2. 128 бит")
                print("3. 192 бит")
                print("0. Выйти из программы")
                cmd_2 = input("Выберите длину ключа: ")
                print("Генерируем ключи шифрования...")
                if cmd_2 == "1":
                    generation(settings, 8)
                    encryption_sym_key(settings)
                    set_iv_value(settings)
                    print("Готово!")
                    break
                elif cmd_2 == "2":
                    generation(settings, 16)
                    encryption_sym_key(settings)
                    set_iv_value(settings)
                    print("Готово!")
                    break
                elif cmd_2 == "3":
                    generation(settings, 24)
                    encryption_sym_key(settings)
                    set_iv_value(settings)
                    print("Готово!")
                    break
                elif cmd_2 == "0":
                    break

        elif cmd == "0":
            break
        else:
            print("Вы ввели не правильное значение")

