from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
import os


def decryption_key(setting: dict, key: bytes):
    """
    Функция дешифрования симметричного ключа асимметричным алгоритмом
    :param setting: dict
    Словарь, содержащий в себе все необходимые файлы
    :param key: bytes
    Симметричный ключ
    :return: Дешифрованный симметричный ключ
    """
    with open(setting['private_key'], 'rb') as pem_in:
        private_bytes = pem_in.read()
    d_private_key = load_pem_private_key(private_bytes, password=None, )
    ds_key = d_private_key.decrypt(key,
                                   padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                                label=None))
    return ds_key


def generation(setting: dict, key_size: int):
    """
    Функция генерации симметричного и асимметричных ключей шифрования
    :param setting: dict
    Словарь, содержащий в себе все необходимые файлы
    :param key_size: int
    Размер симметричного ключа
    :return: None
    """
    key = os.urandom(key_size)
    print("Симметричный ключ сгенерирован!")
    asymmetric_keys = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_key = asymmetric_keys
    public_key = asymmetric_keys.public_key()
    print("Асимметричные ключи сгенерированы!")
    public_pem = setting['public_key']
    with open(public_pem, 'wb') as public_out:
        public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo))
    private_pem = setting['private_key']
    with open(private_pem, 'wb') as private_out:
        private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                    encryption_algorithm=serialization.NoEncryption()))
    with open(setting['symmetric_key'], 'wb', ) as key_file:
        key_file.write(key)


def encryption_sym_key(setting: dict):
    """
    Функция шифрования симметричного ключа
    :param setting: dict
    Словарь, содержащий в себе все необходимые файлы
    :return: None
    """
    with open(setting['symmetric_key'], 'rb', ) as key_file:
        key = key_file.read()
    with open(setting['public_key'], 'rb') as pem_in:
        public_bytes = pem_in.read()
    public_key = load_pem_public_key(public_bytes)
    # десериализация закрытого ключа
    with open(setting['private_key'], 'rb') as pem_in:
        private_bytes = pem_in.read()
    private_key = load_pem_private_key(private_bytes, password=None, )
    sym_key = public_key.encrypt(key,
                                 padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                              label=None))
    print("Симметричный ключ зашифрован!")
    with open(setting['symmetric_key'], 'wb', ) as key_file:
        key_file.write(sym_key)