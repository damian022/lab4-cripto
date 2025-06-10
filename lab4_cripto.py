#!pip install pycryptodome

from Crypto.Cipher import DES, DES3, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64


def ajustar_clave(clave, tamano, algoritmo="GENERIC"):
    clave_bytes = clave.encode()

    if len(clave_bytes) > tamano:
        clave_bytes = clave_bytes[:tamano]
    elif len(clave_bytes) < tamano:
        clave_bytes += get_random_bytes(tamano - len(clave_bytes))

    if algoritmo == "3DES":
        try:
            clave_bytes = DES3.adjust_key_parity(clave_bytes)
        except ValueError:
            print("⚠️ Clave inválida para 3DES. Generando nueva clave segura aleatoria.")
            while True:
                clave_bytes = get_random_bytes(tamano)
                try:
                    clave_bytes = DES3.adjust_key_parity(clave_bytes)
                    break
                except ValueError:
                    continue

    return clave_bytes


def ajustar_iv(iv, tamano):
    iv_bytes = iv.encode()

    if len(iv_bytes) > tamano:
        iv_bytes = iv_bytes[:tamano]
    elif len(iv_bytes) < tamano:
        iv_bytes += get_random_bytes(tamano - len(iv_bytes))

    return iv_bytes


def mostrar_resultados(nombre_algoritmo, clave_bytes, iv_bytes, texto_cifrado, texto_descifrado):
    print(f"\n--- {nombre_algoritmo} ---")
    print(f"Clave usada (bytes): {clave_bytes}")
    print(f"IV usado (bytes): {iv_bytes}")
    print(f"Texto cifrado (hex): {texto_cifrado.hex()}")
    print(f"Texto cifrado (Base64): {base64.b64encode(texto_cifrado).decode()}")
    print(f"Texto descifrado: {texto_descifrado}")


def des_cifrar(clave, iv, texto):
    clave_bytes = ajustar_clave(clave, 8)
    iv_bytes = ajustar_iv(iv, 8)

    cipher = DES.new(clave_bytes, DES.MODE_CBC, iv_bytes)
    texto_cifrado = cipher.encrypt(pad(texto.encode(), DES.block_size))

    decipher = DES.new(clave_bytes, DES.MODE_CBC, iv_bytes)
    texto_descifrado = unpad(decipher.decrypt(texto_cifrado), DES.block_size).decode()

    mostrar_resultados("DES", clave_bytes, iv_bytes, texto_cifrado, texto_descifrado)


def triple_des_cifrar(clave, iv, texto):
    try:
        clave_bytes = ajustar_clave(clave, 16, algoritmo="3DES")
    except ValueError:
        clave_bytes = ajustar_clave(clave, 24, algoritmo="3DES")

    iv_bytes = ajustar_iv(iv, 8)

    cipher = DES3.new(clave_bytes, DES3.MODE_CBC, iv_bytes)
    texto_cifrado = cipher.encrypt(pad(texto.encode(), DES3.block_size))

    decipher = DES3.new(clave_bytes, DES3.MODE_CBC, iv_bytes)
    texto_descifrado = unpad(decipher.decrypt(texto_cifrado), DES3.block_size).decode()

    mostrar_resultados("3DES", clave_bytes, iv_bytes, texto_cifrado, texto_descifrado)


def aes_cifrar(clave, iv, texto):
    clave_bytes = ajustar_clave(clave, 32)
    iv_bytes = ajustar_iv(iv, 16)

    cipher = AES.new(clave_bytes, AES.MODE_CBC, iv_bytes)
    texto_cifrado = cipher.encrypt(pad(texto.encode(), AES.block_size))

    decipher = AES.new(clave_bytes, AES.MODE_CBC, iv_bytes)
    texto_descifrado = unpad(decipher.decrypt(texto_cifrado), AES.block_size).decode()

    mostrar_resultados("AES-256", clave_bytes, iv_bytes, texto_cifrado, texto_descifrado)


def main():
    clave_usuario = input("Ingrese la clave (key): ")
    iv_usuario = input("Ingrese el IV (vector de inicialización): ")
    texto = input("Ingrese el texto a cifrar: ")

    des_cifrar(clave_usuario, iv_usuario, texto)
    triple_des_cifrar(clave_usuario, iv_usuario, texto)
    aes_cifrar(clave_usuario, iv_usuario, texto)


if __name__ == "__main__":
    main()