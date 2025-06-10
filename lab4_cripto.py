#!pip install pycryptodome

from Crypto.Cipher import DES, DES3, AES
from Crypto.Util.Padding import pad, unpad
import base64
import random
import string


def generar_relleno_alfanumerico(cantidad):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=cantidad))


def ajustar_clave(clave, tamano, algoritmo="GENERIC"):
    if len(clave) > tamano:
        clave = clave[:tamano]
    elif len(clave) < tamano:
        clave += generar_relleno_alfanumerico(tamano - len(clave))

    clave_bytes = clave.encode()

    if algoritmo == "3DES":
        try:
            clave_bytes = DES3.adjust_key_parity(clave_bytes)
        except ValueError:
            print("⚠️ Clave inválida para 3DES. Generando nueva clave segura aleatoria.")
            while True:
                clave = generar_relleno_alfanumerico(tamano)
                clave_bytes = clave.encode()
                try:
                    clave_bytes = DES3.adjust_key_parity(clave_bytes)
                    break
                except ValueError:
                    continue

    return clave, clave_bytes


def ajustar_iv(iv, tamano):
    if len(iv) > tamano:
        iv = iv[:tamano]
    elif len(iv) < tamano:
        iv += generar_relleno_alfanumerico(tamano - len(iv))

    iv_bytes = iv.encode()
    return iv, iv_bytes


def mostrar_resultados(nombre_algoritmo, clave_texto, iv_texto, texto_cifrado, texto_descifrado):
    print(f"\n--- {nombre_algoritmo} ---")
    print(f"Clave usada: {clave_texto} (longitud: {len(clave_texto)})")
    print(f"IV usado: {iv_texto}")
    print(f"Texto cifrado (hex): {texto_cifrado.hex()}")
    print(f"Texto cifrado (Base64): {base64.b64encode(texto_cifrado).decode()}")
    print(f"Texto descifrado: {texto_descifrado}")


def des_cifrar(clave, iv, texto):
    clave_texto, clave_bytes = ajustar_clave(clave, 8)
    iv_texto, iv_bytes = ajustar_iv(iv, 8)

    cipher = DES.new(clave_bytes, DES.MODE_CBC, iv_bytes)
    texto_cifrado = cipher.encrypt(pad(texto.encode(), DES.block_size))

    decipher = DES.new(clave_bytes, DES.MODE_CBC, iv_bytes)
    texto_descifrado = unpad(decipher.decrypt(texto_cifrado), DES.block_size).decode()

    mostrar_resultados("DES", clave_texto, iv_texto, texto_cifrado, texto_descifrado)


def triple_des_cifrar(clave, iv, texto):
    # Intentar primero con clave de 16 bytes
    try:
        clave_texto, clave_bytes = ajustar_clave(clave, 16, algoritmo="3DES")
        cipher = DES3.new(clave_bytes, DES3.MODE_CBC, ajustar_iv(iv, 8)[1])
    except ValueError:
        # Fallback a 24 bytes si no es válida
        clave_texto, clave_bytes = ajustar_clave(clave, 24, algoritmo="3DES")

    iv_texto, iv_bytes = ajustar_iv(iv, 8)

    cipher = DES3.new(clave_bytes, DES3.MODE_CBC, iv_bytes)
    texto_cifrado = cipher.encrypt(pad(texto.encode(), DES3.block_size))

    decipher = DES3.new(clave_bytes, DES3.MODE_CBC, iv_bytes)
    texto_descifrado = unpad(decipher.decrypt(texto_cifrado), DES3.block_size).decode()

    mostrar_resultados("3DES", clave_texto, iv_texto, texto_cifrado, texto_descifrado)


def aes_cifrar(clave, iv, texto):
    clave_texto, clave_bytes = ajustar_clave(clave, 32)
    iv_texto, iv_bytes = ajustar_iv(iv, 16)

    cipher = AES.new(clave_bytes, AES.MODE_CBC, iv_bytes)
    texto_cifrado = cipher.encrypt(pad(texto.encode(), AES.block_size))

    decipher = AES.new(clave_bytes, AES.MODE_CBC, iv_bytes)
    texto_descifrado = unpad(decipher.decrypt(texto_cifrado), AES.block_size).decode()

    mostrar_resultados("AES-256", clave_texto, iv_texto, texto_cifrado, texto_descifrado)


def main():
    clave_usuario = input("Ingrese la clave (key): ")
    iv_usuario = input("Ingrese el IV (vector de inicialización): ")
    texto = input("Ingrese el texto a cifrar: ")

    des_cifrar(clave_usuario, iv_usuario, texto)
    triple_des_cifrar(clave_usuario, iv_usuario, texto)
    aes_cifrar(clave_usuario, iv_usuario, texto)


if __name__ == "__main__":
    main()