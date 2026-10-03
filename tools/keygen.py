#!/usr/bin/env python3
"""
Genera las claves ECDSA P-256 de cada placa y su archivo secrets.h.

Uso:
    python keygen.py --ssid "MiRed" --password "MiClave" ESP32_Bryan=192.168.0.108 ESP32_Christopher=192.168.0.109

- Las claves privadas se guardan en tools/keys/<ID>.pem y se REUTILIZAN si ya existen:
  puedes volver a correrlo para cambiar IPs o el WiFi sin tener que cambiar claves.
- Crea tools/secrets/<ID>/secrets.h para cada placa. Copia el de cada placa
  a la carpeta del sketch (nodo_p2p/) antes de subirlo a ESA placa.
- keys/ y secrets/ estan en .gitignore: contienen claves privadas y la clave del WiFi.

Requiere: pip install cryptography
"""
import argparse
import ipaddress
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

AQUI = os.path.dirname(os.path.abspath(__file__))
DIR_KEYS = os.path.join(AQUI, "keys")
DIR_SECRETS = os.path.join(AQUI, "secrets")


def cargar_o_crear_clave(dev_id):
    ruta = os.path.join(DIR_KEYS, f"{dev_id}.pem")
    if os.path.exists(ruta):
        with open(ruta, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None), False
    clave = ec.generate_private_key(ec.SECP256R1())
    with open(ruta, "wb") as f:
        f.write(clave.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()))
    return clave, True


def bytes_c(b, por_linea=16, sangria="        "):
    lineas = []
    for i in range(0, len(b), por_linea):
        lineas.append(sangria + ", ".join(f"0x{x:02X}" for x in b[i:i + por_linea]))
    return ",\n".join(lineas)


def c_str(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def main():
    ap = argparse.ArgumentParser(description="Genera claves y secrets.h para cada placa")
    ap.add_argument("--ssid", default="TU_RED_2.4GHz", help="Red WiFi de 2.4 GHz")
    ap.add_argument("--password", default="TU_PASSWORD", help="Clave del WiFi")
    ap.add_argument("dispositivos", nargs="+", metavar="ID=IP",
                    help="Ejemplo: ESP32_Bryan=192.168.0.108")
    args = ap.parse_args()

    dispositivos = []
    for item in args.dispositivos:
        if "=" not in item:
            sys.exit(f"Formato invalido '{item}'. Usa ID=IP, por ejemplo ESP32_Bryan=192.168.0.108")
        dev_id, ip = item.split("=", 1)
        if not (1 <= len(dev_id) <= 19) or not all(c.isalnum() or c in "_-" for c in dev_id):
            sys.exit(f"ID invalido '{dev_id}': 1 a 19 caracteres (letras, numeros, _ o -)")
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            sys.exit(f"IP invalida '{ip}'")
        if any(d[0] == dev_id for d in dispositivos):
            sys.exit(f"ID repetido: {dev_id}")
        dispositivos.append((dev_id, ip))
    if len(dispositivos) < 2:
        sys.exit("Se necesitan al menos 2 dispositivos.")

    os.makedirs(DIR_KEYS, exist_ok=True)
    claves = {}
    for dev_id, _ in dispositivos:
        clave, nueva = cargar_o_crear_clave(dev_id)
        claves[dev_id] = clave
        print(f"{'Nueva clave' if nueva else 'Clave existente'}: {dev_id}")

    lista = []
    for dev_id, ip in dispositivos:
        pub = claves[dev_id].public_key().public_bytes(serialization.Encoding.X962,
                                                       serialization.PublicFormat.UncompressedPoint)
        lista.append(f"    {{ {c_str(dev_id)}, {c_str(ip)}, {{\n{bytes_c(pub)} }} }}")
    lista_c = ",\n".join(lista)

    for dev_id, _ in dispositivos:
        priv = claves[dev_id].private_numbers().private_value.to_bytes(32, "big")
        contenido = f"""// secrets.h de {dev_id}. Generado por tools/keygen.py. NO SUBIR A GITHUB.
#pragma once

#define WIFI_SSID {c_str(args.ssid)}
#define WIFI_PASS {c_str(args.password)}
#define MY_ID     {c_str(dev_id)}

// Clave privada ECDSA P-256 de ESTA placa (escalar de 32 bytes)
static const uint8_t MY_PRIVATE_KEY[32] = {{
{bytes_c(priv)}
}};

// Dispositivos autorizados: ID, IP y clave publica (la propia incluida)
static const Dispositivo DISPOSITIVOS[] = {{
{lista_c}
}};
"""
        carpeta = os.path.join(DIR_SECRETS, dev_id)
        os.makedirs(carpeta, exist_ok=True)
        with open(os.path.join(carpeta, "secrets.h"), "w", encoding="utf-8") as f:
            f.write(contenido)
        print(f"  -> {os.path.relpath(os.path.join(carpeta, 'secrets.h'), AQUI)}")

    print("\nCopia el secrets.h de cada placa a la carpeta nodo_p2p/ antes de subirle el codigo.")


if __name__ == "__main__":
    main()
