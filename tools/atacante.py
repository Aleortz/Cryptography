#!/usr/bin/env python3
"""
Pruebas de seguridad (Seccion 4) contra una placa, desde la laptop.

  python atacante.py <IP_placa> desconocido
      Un dispositivo que no esta en la lista intenta conectarse.

  python atacante.py <IP_placa> suplantar ESP32_Christopher
      Un intruso usa el ID de una placa autorizada, pero no tiene su clave privada.

  python atacante.py <IP_placa> inyectar
      Envia un paquete de datos forjado directamente al puerto, sin handshake.

La placa debe rechazar los tres casos y mostrar [ALERTA] en su Monitor Serie.
Requiere: pip install cryptography
"""
import os
import socket
import struct
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

PUERTO = 8080
MAGIC = b"P1v1"
HELLO_REPLY_LEN = 1 + 20 + 16 + 65 + 64


def recibir(s, n):
    datos = b""
    while len(datos) < n:
        trozo = s.recv(n - len(datos))
        if not trozo:
            break
        datos += trozo
    return datos


def hello(dev_id):
    efimera = ec.generate_private_key(ec.SECP256R1())
    epub = efimera.public_key().public_bytes(serialization.Encoding.X962,
                                             serialization.PublicFormat.UncompressedPoint)
    return MAGIC + dev_id.encode().ljust(20, b"\0") + os.urandom(16) + epub


def conectar(ip, puerto):
    s = socket.create_connection((ip, puerto), timeout=10)
    s.settimeout(10)
    return s


def desconocido(ip, puerto):
    print("[*] Conectando como 'ESP32_Intruso' (no esta en la lista de autorizados)...")
    s = conectar(ip, puerto)
    s.sendall(hello("ESP32_Intruso"))
    r = recibir(s, HELLO_REPLY_LEN)
    s.close()
    if len(r) == HELLO_REPLY_LEN and r[0] == 0:
        print("[OK] La placa RECHAZO al dispositivo no autorizado (status = 0).")
    else:
        print(f"[!!] Respuesta inesperada: {r[:1].hex() if r else 'conexion cerrada'}")


def suplantar(ip, puerto, dev_id):
    print(f"[*] Conectando como '{dev_id}' con una clave privada FALSA...")
    s = conectar(ip, puerto)
    h = hello(dev_id)
    s.sendall(h)
    r = recibir(s, HELLO_REPLY_LEN)
    if len(r) != HELLO_REPLY_LEN or r[0] != 1:
        print("[OK] La placa rechazo el ID desde el primer mensaje.")
        s.close()
        return
    print("[*] La placa respondio y firmo su parte. Enviando una firma hecha con una clave que no es la de "
          f"{dev_id}...")
    T = hashes.Hash(hashes.SHA256())
    T.update(h + r[1:1 + 20 + 16 + 65])
    T = T.finalize()
    clave_falsa = ec.generate_private_key(ec.SECP256R1())
    der = clave_falsa.sign(b"P1-INIT" + T, ec.ECDSA(hashes.SHA256()))
    rr, ss = decode_dss_signature(der)
    s.sendall(rr.to_bytes(32, "big") + ss.to_bytes(32, "big"))
    resultado = recibir(s, 1)
    s.close()
    if resultado == b"\x00" or resultado == b"":
        print("[OK] La placa RECHAZO la firma: sin la clave privada real no se puede suplantar a "
              f"{dev_id}.")
    else:
        print(f"[!!] La placa acepto la sesion (respuesta {resultado.hex()}). Esto NO deberia pasar.")


def inyectar(ip, puerto):
    print("[*] Enviando un paquete de datos forjado, sin handshake...")
    s = conectar(ip, puerto)
    cabecera = (b"ESP32_Christopher".ljust(20, b"\0") + struct.pack("<II", 0x12345678, 1) +
                os.urandom(12) + struct.pack("<H", 24))
    paquete = b"\x01" + cabecera + os.urandom(24) + os.urandom(16)
    s.sendall(paquete.ljust(105, b"\0"))
    try:
        resp = s.recv(16)
    except socket.timeout:
        resp = None
    s.close()
    if not resp:
        print("[OK] La placa descarto el paquete forjado y cerro la conexion.")
    else:
        print(f"[!!] Respuesta inesperada: {resp.hex()}")


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    ip, modo = sys.argv[1], sys.argv[2]
    puerto = int(os.environ.get("PUERTO", PUERTO))
    if modo == "desconocido":
        desconocido(ip, puerto)
    elif modo == "suplantar" and len(sys.argv) >= 4:
        suplantar(ip, puerto, sys.argv[3])
    elif modo == "inyectar":
        inyectar(ip, puerto)
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
