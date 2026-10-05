#!/usr/bin/env python3
"""
Dispositivo D (atacante) para el Proyecto 1 - Secure Wireless Messaging.

Se ejecuta en la laptop, en la MISMA red WiFi que las placas, y ataca el
puerto 8080 de una placa legitima. Demuestra que un atacante sin la clave privada
de un dispositivo autorizado no puede entrar a una sesion ni hacerse pasar por una placa.

Uso:
    python atacante.py <IP_de_la_placa> no-autorizado
        D se conecta con un ID que no esta en la lista. La placa debe
        rechazarlo de inmediato (status = 0), antes de cualquier handshake.

    python atacante.py <IP_de_la_placa> suplantar <ID_valido>
        D usa el ID de una placa autorizada (ej. ESP32_Christopher) pero
        NO tiene su clave privada. El handshake avanza hasta la autenticacion
        y ahi la placa detecta que la firma no es valida y lo rechaza.

    python atacante.py <IP_de_la_placa> miembro <ID_que_finge> <ID_cuya_clave_posee>
        Atacante INTERNO: D posee la clave privada valida de un miembro del
        grupo (keys/<ID_cuya_clave_posee>.key) e intenta usarla para hacerse
        pasar por OTRO dispositivo. La placa verifica la firma contra la clave
        publica de <ID_que_finge> y lo rechaza: robar una placa NO permite
        suplantar a las demas. (Requiere: pip install cryptography)

    python atacante.py <IP_de_la_placa> inyectar
        D manda un paquete de datos forjado sin handshake. La placa lo
        descarta por protocolo invalido.

Los modos no-autorizado, suplantar e inyectar usan solo la biblioteca estandar de Python.
En cada caso, mira el Monitor Serie de la placa: debe aparecer una
[ALERTA] identificando el intento.
"""
import os
import socket
import struct
import sys

PUERTO = 8080
MAGIC = b"P1v4"          # debe coincidir con MAGIC en el .ino
DH_LEN = 256
HELLO_LEN = 4 + 20 + 16 + DH_LEN          # 296
HELLOREPLY_LEN = 1 + 20 + 16 + DH_LEN + 64  # 357 (status, id, nonce, dh_pub, firma)
TIMEOUT = 20            # el DH de 2048 bits de la placa tarda varios segundos


def recibir(sock, n):
    datos = b""
    while len(datos) < n:
        try:
            trozo = sock.recv(n - len(datos))
        except socket.timeout:
            break
        if not trozo:
            break
        datos += trozo
    return datos


def conectar(ip):
    s = socket.create_connection((ip, PUERTO), timeout=TIMEOUT)
    s.settimeout(TIMEOUT)
    return s


def construir_hello(dev_id):
    # magic || id[20] || nonce[16] || dh_pub[256]  (dh_pub basura: D no tiene ninguna clave autorizada)
    return (MAGIC
            + dev_id.encode().ljust(20, b"\0")[:20]
            + os.urandom(16)
            + os.urandom(DH_LEN))


def no_autorizado(ip):
    dev_id = "ESP32_Hacker"
    print(f"[D] Conectando a {ip}:{PUERTO} como '{dev_id}' (NO esta en la lista)...")
    s = conectar(ip)
    s.sendall(construir_hello(dev_id))
    r = recibir(s, HELLOREPLY_LEN)
    s.close()
    if r and r[0] == 0:
        print("[OK] La placa RECHAZO al dispositivo no autorizado (status = 0).")
        print("     Revisa el Monitor Serie: [ALERTA] Intento de acceso ... NO AUTORIZADO")
    elif not r:
        print("[OK] La placa cerro la conexion sin dar sesion.")
    else:
        print(f"[!!] Respuesta inesperada (primer byte = {r[0]}). No deberia aceptar.")


def suplantar(ip, dev_id):
    print(f"[D] Conectando a {ip}:{PUERTO} haciendome pasar por '{dev_id}', pero SIN su clave privada...")
    s = conectar(ip)
    s.sendall(construir_hello(dev_id))
    r = recibir(s, HELLOREPLY_LEN)
    if not r or r[0] != 1:
        print("[OK] La placa rechazo el intento ya en el primer mensaje.")
        s.close()
        return
    print("[D] La placa respondio y firmo su parte (eso es normal: el ID si existe).")
    print("[D] Ahora D deberia FIRMAR con la clave privada de ese dispositivo. Como NO la tiene, manda una firma inventada...")
    s.sendall(os.urandom(64))               # Finish con una firma falsa
    resultado = recibir(s, 1)
    s.close()
    if resultado in (b"\x00", b""):
        print("[OK] La placa RECHAZO la autenticacion: sin la clave privada no se puede suplantar.")
        print("     Revisa el Monitor Serie: [ALERTA] Intento de manipulacion/suplantacion ...")
    else:
        print(f"[!!] La placa acepto la sesion (resultado = {resultado.hex()}). NO deberia pasar.")


def miembro(ip, dev_id, id_clave, keydir="keys"):
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    except ImportError:
        sys.exit("Este modo necesita: pip install cryptography")
    ruta = os.path.join(keydir, id_clave + ".key")
    with open(ruta) as f:
        priv = ec.derive_private_key(int(f.read().strip(), 16), ec.SECP256R1())
    print(f"[D] Atacante INTERNO: poseo la clave valida de '{id_clave}' y la uso para fingir ser '{dev_id}'...")
    s = conectar(ip)
    h = construir_hello(dev_id)
    s.sendall(h)
    r = recibir(s, HELLOREPLY_LEN)
    if len(r) != HELLOREPLY_LEN or r[0] != 1:
        print("[OK] La placa rechazo el intento ya en el primer mensaje.")
        s.close()
        return
    d = hashes.Hash(hashes.SHA256())
    d.update(h + r[1:1 + 20 + 16 + DH_LEN])
    T = d.finalize()
    rr, ss = decode_dss_signature(priv.sign(b"P1-INIT" + T, ec.ECDSA(hashes.SHA256())))
    s.sendall(rr.to_bytes(32, "big") + ss.to_bytes(32, "big"))
    resultado = recibir(s, 1)
    s.close()
    if resultado in (b"\x00", b""):
        print(f"[OK] La placa RECHAZO la firma: la clave de '{id_clave}' no sirve para ser '{dev_id}'.")
    elif dev_id == id_clave:
        print(f"[OK] (control) Sesion legitima aceptada: '{id_clave}' firmo como si mismo con su propia clave.")
    else:
        print(f"[!!] La placa acepto la sesion (resultado = {resultado.hex()}). NO deberia pasar.")


def inyectar(ip):
    print(f"[D] Enviando a {ip}:{PUERTO} un paquete de datos FORJADO, sin handshake...")
    s = conectar(ip)
    # Trama FRAME_DATA (0x01) + PacketHeader + ciphertext basura + tag basura.
    # Sin handshake, la placa espera un Hello con MAGIC; esto no lo tiene.
    header = (b"ESP32_Christopher".ljust(20, b"\0")
              + struct.pack("<II", 0xDEADBEEF, 1)   # SID y SEQ inventados
              + os.urandom(12)                        # nonce
              + struct.pack("<H", 24))                # cipher_len
    paquete = b"\x01" + header + os.urandom(24) + os.urandom(16)
    s.sendall(paquete)
    try:
        resp = s.recv(16)
    except socket.timeout:
        resp = None
    s.close()
    if not resp:
        print("[OK] La placa descarto el paquete forjado y cerro la conexion.")
        print("     Revisa el Monitor Serie: [ALERTA] Conexion sin handshake / protocolo invalido ...")
    else:
        print(f"[!!] Respuesta inesperada: {resp.hex()}")


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    ip, modo = sys.argv[1], sys.argv[2]
    if modo == "no-autorizado":
        no_autorizado(ip)
    elif modo == "suplantar" and len(sys.argv) >= 4:
        suplantar(ip, sys.argv[3])
    elif modo == "miembro" and len(sys.argv) >= 5:
        miembro(ip, sys.argv[3], sys.argv[4])
    elif modo == "inyectar":
        inyectar(ip)
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()