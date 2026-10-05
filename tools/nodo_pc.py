#!/usr/bin/env python3
"""
Dispositivo C (peer LEGITIMO simulado) para el Proyecto 1.

Corre en la laptop y se comporta igual que una placa ESP32: hace el handshake
Diffie-Hellman de 2048 bits, se autentica con una FIRMA ECDSA P-256 hecha con su
propia clave privada, deriva las claves con HKDF, cifra/descifra con AES-256-GCM
y avanza la cadena de claves por cada mensaje. Su protocolo es identico al de
nodo_pc.py <-> nodo_p2p.ino (MAGIC "P1v4").

Cada dispositivo tiene su PROPIO par de claves y cada dueño genera SOLO el suyo
(la clave privada nunca sale de su equipo; solo se comparte la publica):

    pip install cryptography
    python nodo_pc.py --genkey ESP32_Bryan ESP32_Demian   # Bryan: su placa + el nodo simulado de su laptop
    python nodo_pc.py --genkey ESP32_Christopher          # Christopher, en SU equipo

Cada --genkey crea keys/<ID>.key (PRIVADA) y agrega la publica a keys/authorized.txt,
sin borrar las que ya hubiera. Luego se intercambian solo las claves PUBLICAS:

    python nodo_pc.py --addpub ESP32_Christopher=04...    # agrega la publica de otro
    python nodo_pc.py --block                              # imprime el bloque AUTORIZADOS para el .ino

NUNCA subas keys/*.key a GitHub.

Uso normal:
    python nodo_pc.py --id ESP32_Demian --ip <IP_de_esta_laptop>

  --ip es la IPv4 WiFi de la laptop (ipconfig).
  --keydir (por defecto keys) debe contener <ID>.key y authorized.txt.

Comandos en consola (igual que el Monitor Serie de las placas):
    texto           envia a todas las placas conectadas
    @ID texto       envia solo a esa placa
    1..6            pruebas (1 normal, 2 ciphertext, 3 TAG, 4 replay, 5 ID_S, 6 forjado)
    p               estado de las placas
    k               estado de las cadenas de claves
    q               salir
"""
import argparse
import os
import socket
import struct
import sys
import threading
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ---- Debe coincidir con nodo_p2p.ino ----
MAGIC = b"P1v4"
PUERTO = 8080
PUERTO_DESC = 8081
DH_LEN = 256
DH_PRIV_BYTES = 32
DH_G = 2
DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)

HELLO = struct.Struct("<4s20s16s256s")                 # magic, id, nonce, dh_pub
HELLOREPLY = struct.Struct("<B20s16s256s64s")          # status, id, nonce, dh_pub, firma (r||s)
HEADER = struct.Struct("<20sII12sH")                   # sender_id, sid, seq, nonce, cipher_len
ACK = struct.Struct("<IB")                             # seq, status
FRAME_DATA, FRAME_ACK = 0x01, 0x02
MENSAJE_PRUEBA = "Temp: 24.5C | Hum: 60% | Nodo Activo"

CHUNK = 64


def hx(b):  # imprime hex en bloques, como printHex del .ino
    s = b.hex().upper()
    return "\n".join(s[i:i + CHUNK] for i in range(0, len(s), CHUNK))


def sha256(b):
    h = hashes.Hash(hashes.SHA256())
    h.update(b)
    return h.finalize()


def firmar(priv, etiqueta, T):
    """ECDSA P-256 sobre SHA256(etiqueta || T); devuelve r||s (64 bytes), como el .ino."""
    r, s = decode_dss_signature(priv.sign(etiqueta + T, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verificar(pub, etiqueta, T, sig):
    """Verifica con la clave publica GRABADA del dispositivo (nunca con una recibida)."""
    if len(sig) != 64:
        return False
    der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
    try:
        pub.verify(der, etiqueta + T, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def pub_bytes(pub):
    return pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def huella_pub(pub):
    return sha256(pub_bytes(pub))[:4].hex().upper()


def hkdf(salt, ikm, info, length=32):
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def msg_key(ck):      # MK_n = HKDF(CK_n, "P1-MSG"): clave de UN solo mensaje (igual que el .ino)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"P1-MSG").derive(ck)


def next_chain(ck):   # CK_(n+1) = HKDF(CK_n, "P1-CHAIN"): el estado avanza (igual que el .ino)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"P1-CHAIN").derive(ck)


class Peer:
    def __init__(self, pid):
        self.id = pid
        self.pub = None
        self.sock = None
        self.activo = False
        self.k_tx = self.k_rx = None
        self.sid = 0
        self.tx_seq = 0
        self.rx_last = 0
        self.ultimo_frame = None
        self.lock = threading.Lock()


class NodoC:
    def __init__(self, my_id, my_ip, priv, autorizados, verbose=True):
        # autorizados: dict ID -> clave publica (objeto EllipticCurvePublicKey)
        self.id = my_id
        self.ip = my_ip
        self.priv = priv
        self.verbose = verbose
        self.peers = {}
        for pid, pub in autorizados.items():
            if pid != my_id:
                self.peers[pid] = Peer(pid)
                self.peers[pid].pub = pub
        self.ips = {}
        self.run = True

    # ---------- transcript y derivacion ----------
    def transcript(self, hello, rid, rnonce, rpub):
        return sha256(hello + rid + rnonce + rpub)

    def derivar(self, z, hnonce, rnonce, T):
        okm = hkdf(hnonce + rnonce, z, b"P1-KEYS" + T, 68)
        return okm[:32], okm[32:64], struct.unpack("<I", okm[64:68])[0]

    # ---------- descubrimiento ----------
    def anunciar_loop(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        a = MAGIC + self.id.encode().ljust(20, b"\0")[:20]
        while self.run:
            try:
                s.sendto(a, ("255.255.255.255", PUERTO_DESC))
            except OSError:
                pass
            time.sleep(2)

    def escuchar_anuncios(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("", PUERTO_DESC))
        except OSError as e:
            print(f"[AVISO] No pude escuchar anuncios UDP ({e}). Uso --peer si hace falta.")
            return
        s.settimeout(1)
        while self.run:
            try:
                data, addr = s.recvfrom(64)
            except socket.timeout:
                continue
            except OSError:
                break
            if len(data) < 24 or data[:4] != MAGIC:
                continue
            pid = data[4:24].split(b"\0")[0].decode(errors="ignore")
            if pid in self.peers and self.ips.get(pid) != addr[0]:
                self.ips[pid] = addr[0]
                print(f"[DESCUBIERTA] {pid} en {addr[0]}")

    # ---------- servidor: aceptar handshakes entrantes ----------
    def servidor_loop(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("", PUERTO))
        s.listen(8)
        s.settimeout(1)
        while self.run:
            try:
                c, addr = s.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self.atender_entrante, args=(c, addr), daemon=True).start()

    def recv_exact(self, c, n):
        buf = b""
        while len(buf) < n:
            try:
                t = c.recv(n - len(buf))
            except (socket.timeout, OSError):
                break
            if not t:
                break
            buf += t
        return buf

    def atender_entrante(self, c, addr):
        c.settimeout(20)
        hello = self.recv_exact(c, HELLO.size)
        if len(hello) != HELLO.size:
            c.close()
            return
        magic, rid_b, rnonce, rpub = HELLO.unpack(hello)
        if magic != MAGIC:
            print(f"[ALERTA] Datos sin protocolo valido desde {addr[0]}. Descartado.")
            c.close()
            return
        rid = rid_b.split(b"\0")[0].decode(errors="ignore")
        if rid not in self.peers:
            print(f"[ALERTA] Intento de acceso desde dispositivo NO AUTORIZADO '{rid}' ({addr[0]}). Rechazado.")
            c.sendall(HELLOREPLY.pack(0, b"", b"", b"", b""))
            c.close()
            return

        priv = int.from_bytes(os.urandom(DH_PRIV_BYTES), "big")
        pub = pow(DH_G, priv, DH_P).to_bytes(DH_LEN, "big")
        nonce = os.urandom(16)
        T = self.transcript(hello, self.id.encode().ljust(20, b"\0")[:20], nonce, pub)
        sig = firmar(self.priv, b"P1-RESP", T)
        c.sendall(HELLOREPLY.pack(1, self.id.encode().ljust(20, b"\0")[:20], nonce, pub, sig))

        fin = self.recv_exact(c, 64)
        if len(fin) != 64:
            c.close()
            return
        if not verificar(self.peers[rid].pub, b"P1-INIT", T, fin):
            print(f"[ALERTA] Intento de manipulacion/suplantacion detectado desde '{rid}' ({addr[0]}): firma invalida, no posee la clave privada de ese dispositivo.")
            c.sendall(b"\x00")
            c.close()
            return
        c.sendall(b"\x01")

        pub_peer = int.from_bytes(rpub, "big")
        if not (2 <= pub_peer < DH_P - 1):
            c.close()
            return
        z = pow(pub_peer, priv, DH_P).to_bytes(DH_LEN, "big")
        k_i2r, k_r2i, sid = self.derivar(z, rnonce, nonce, T)
        # respondedor: recibo con k_i->r, envio con k_r->i
        self._activar(rid, c, k_rx=k_i2r, k_tx=k_r2i, sid=sid, z=z, pub=pub, rol="respondedor")

    # ---------- cliente: iniciar handshake saliente ----------
    def conectar(self, pid):
        ip = self.ips.get(pid)
        if not ip:
            return
        try:
            c = socket.create_connection((ip, PUERTO), timeout=20)
        except OSError:
            return
        c.settimeout(20)
        print(f"\n[..] Iniciando handshake Diffie-Hellman con {pid} (puede tardar unos segundos)...")
        priv = int.from_bytes(os.urandom(DH_PRIV_BYTES), "big")
        pub = pow(DH_G, priv, DH_P).to_bytes(DH_LEN, "big")
        nonce = os.urandom(16)
        hello = HELLO.pack(MAGIC, self.id.encode().ljust(20, b"\0")[:20], nonce, pub)
        c.sendall(hello)
        rep = self.recv_exact(c, HELLOREPLY.size)
        if len(rep) != HELLOREPLY.size:
            print(f"[X] {pid} no respondio al handshake.")
            c.close()
            return
        status, rid_b, rnonce, rpub, rsig = HELLOREPLY.unpack(rep)
        if status != 1:
            print(f"[X] {pid} me rechazo (¿no estoy en su lista?).")
            c.close()
            return
        T = self.transcript(hello, rid_b, rnonce, rpub)
        if not verificar(self.peers[pid].pub, b"P1-RESP", T, rsig):
            print(f"[ALERTA] {pid} NO demostro ser quien dice (firma invalida): posible suplantacion o MITM.")
            c.close()
            return
        c.sendall(firmar(self.priv, b"P1-INIT", T))
        res = self.recv_exact(c, 1)
        if res != b"\x01":
            print(f"[X] {pid} rechazo mi firma (¿mi clave publica no coincide en su lista?).")
            c.close()
            return
        pub_peer = int.from_bytes(rpub, "big")
        z = pow(pub_peer, priv, DH_P).to_bytes(DH_LEN, "big")
        k_i2r, k_r2i, sid = self.derivar(z, nonce, rnonce, T)
        # iniciador: envio con k_i->r, recibo con k_r->i
        self._activar(pid, c, k_tx=k_i2r, k_rx=k_r2i, sid=sid, z=z, pub=pub, rol="iniciador")

    def _activar(self, pid, c, k_tx, k_rx, sid, z, pub, rol):
        p = self.peers[pid]
        with p.lock:
            if p.activo and p.sock:
                try:
                    p.sock.close()
                except OSError:
                    pass
            p.sock, p.k_tx, p.k_rx, p.sid = c, k_tx, k_rx, sid
            p.tx_seq = p.rx_last = 0
            p.ultimo_frame = None
            p.activo = True
        print(f"\n==== Clave de sesion establecida con {pid} ====")
        print(f"Rol: {rol} | SID: 0x{sid:08X}")
        if self.verbose:
            print("Mi clave publica DH (256 bytes):\n" + hx(pub))
            print("Secreto compartido DH (z):\n" + hx(z))
            print("CK_tx inicial:\n" + hx(k_tx))
            print("CK_rx inicial:\n" + hx(k_rx))
        print("=============================================\n")
        threading.Thread(target=self.rx_loop, args=(pid,), daemon=True).start()

    # ---------- recepcion de datos/acks ----------
    def rx_loop(self, pid):
        p = self.peers[pid]
        c = p.sock
        while self.run and p.activo:
            tipo = self.recv_exact(c, 1)
            if not tipo:
                break
            if tipo[0] == FRAME_DATA:
                self.recibir_data(p)
            elif tipo[0] == FRAME_ACK:
                self.recibir_ack(p)
            else:
                break
        p.activo = False
        print(f"[-] Sesion con {pid} cerrada.")

    def recibir_data(self, p):
        hdr = self.recv_exact(p.sock, HEADER.size)
        if len(hdr) != HEADER.size:
            p.activo = False
            return
        sender_b, sid, seq, nonce, clen = HEADER.unpack(hdr)
        ct = self.recv_exact(p.sock, clen)
        tag = self.recv_exact(p.sock, 16)
        if len(ct) != clen or len(tag) != 16:
            p.activo = False
            return
        sender = sender_b.split(b"\0")[0].decode(errors="ignore")
        print(f"\n<<< MENSAJE RECIBIDO de: {sender} (SEQ {seq}) >>>")
        mk = msg_key(p.k_rx)
        if self.verbose:
            print("Ciphertext:\n" + hx(ct))
            print("CK_rx (estado de la cadena):\n" + hx(p.k_rx))
            print("MK (clave de este mensaje):\n" + hx(mk))
        motivo = None
        pt = None
        if sender != p.id:
            motivo = "Remitente (ID_S) no coincide con la sesion"
        elif sid != p.sid:
            motivo = "Session ID (SID) invalido"
        elif seq <= p.rx_last:
            motivo = "REPLAY detectado (SEQ repetido o antiguo)"
        else:
            try:
                pt = AESGCM(mk).decrypt(nonce, ct + tag, hdr)
            except Exception:
                motivo = "Fallo de autenticacion GCM (ciphertext, cabecera o TAG alterados, o paquete forjado)"
        p.sock.sendall(bytes([FRAME_ACK]) + ACK.pack(seq, 0 if motivo else 1))
        if motivo:
            print(f"[RECHAZADO] Paquete de {p.id} (SEQ {seq}) BLOQUEADO. Razon: {motivo}")
            print(f"[ALERTA] Intento de manipulacion detectado en la sesion con {p.id}.")
        else:
            p.rx_last = seq
            print("TEXTO DESCIFRADO (plaintext recuperado):\n" + pt.decode(errors="replace"))
            print(f"[OK] Mensaje integro y autentico de {p.id}.")
            p.k_rx = next_chain(p.k_rx)
            if self.verbose:
                print("[CADENA] Nuevo CK_rx:\n" + hx(p.k_rx))

    def recibir_ack(self, p):
        a = self.recv_exact(p.sock, ACK.size)
        if len(a) != ACK.size:
            return
        seq, status = ACK.unpack(a)
        print(f"[ACK <- {p.id}] SEQ {seq}: {'ACEPTADO' if status else 'RECHAZADO'}")

    # ---------- envio ----------
    def enviar(self, p, texto, modo):
        data = texto.encode()[:1024]
        p.tx_seq += 1
        seq = p.tx_seq
        nonce = os.urandom(8) + struct.pack("<I", seq)
        sender = self.id
        mk = msg_key(p.k_tx)
        clave = mk
        if modo == 6:
            clave = os.urandom(32)
            print(f"[TEST -> {p.id}] Inyectando paquete forjado (clave que no es la de la sesion)")
        if modo == 5:
            sender = "ESP32_Intruso"
            print(f"[TEST -> {p.id}] Falsificando el remitente (ID_S)")
        hdr = HEADER.pack(sender.encode().ljust(20, b"\0")[:20], p.sid, seq, nonce, len(data))
        ctag = AESGCM(clave).encrypt(nonce, data, hdr)
        ct, tag = ctag[:-16], ctag[-16:]
        if modo == 2:
            ct = bytes([ct[0] ^ 0xFF]) + ct[1:]
            print(f"[TEST -> {p.id}] Alterando 1 byte del ciphertext")
        if modo == 3:
            tag = bytes([tag[0] ^ 0xFF]) + tag[1:]
            print(f"[TEST -> {p.id}] Alterando 1 byte del TAG")
        frame = bytes([FRAME_DATA]) + hdr + ct + tag
        print(f"\n>>> ENVIANDO a {p.id} (SEQ {seq}) <<<")
        if self.verbose:
            print("Plaintext:\n" + texto)
            print("CK_tx (estado de la cadena):\n" + hx(p.k_tx))
            print("MK (clave de este mensaje):\n" + hx(clave))
            print("Ciphertext:\n" + hx(ct))
        p.ultimo_frame = frame
        p.sock.sendall(frame)
        if modo != 6:
            p.k_tx = next_chain(p.k_tx)
            if self.verbose:
                print("[CADENA] Nuevo CK_tx:\n" + hx(p.k_tx))

    def replay(self, p):
        if not p.ultimo_frame:
            print(f"[TEST -> {p.id}] Primero envia un mensaje normal.")
            return
        print(f"[TEST -> {p.id}] REPLAY: retransmitiendo el ultimo paquete, identico.")
        p.sock.sendall(p.ultimo_frame)

    # ---------- consola ----------
    def consola(self):
        while self.run:
            try:
                linea = input()
            except (EOFError, KeyboardInterrupt):
                self.run = False
                break
            if not linea:
                continue
            if linea == "q":
                self.run = False
                break
            if linea == "p":
                print(f"\nYo: {self.id} ({self.ip})")
                for pid, p in self.peers.items():
                    est = f"CONECTADO (SID 0x{p.sid:08X}, TX {p.tx_seq}, RX {p.rx_last})" if p.activo else \
                          (f"en {self.ips[pid]}, desconectado" if pid in self.ips else "no descubierta")
                    print(f" - {pid:19s} {est}")
                print()
                continue
            if linea == "k":
                for pid, p in self.peers.items():
                    if p.activo:
                        print(f"Con {pid}:\n  CK_tx:\n{hx(p.k_tx)}\n  CK_rx:\n{hx(p.k_rx)}")
                print()
                continue
            destino, texto = None, linea
            if linea[0] == "@":
                part = linea.split(" ", 1)
                destino = part[0][1:]
                texto = part[1] if len(part) > 1 else ""
                if destino not in self.peers:
                    print(f"No conozco '{destino}'")
                    continue
            modo = 1
            if len(texto) == 1 and texto in "123456":
                modo = int(texto)
                texto = MENSAJE_PRUEBA
            enviados = 0
            for pid, p in self.peers.items():
                if destino and pid != destino:
                    continue
                if not p.activo:
                    continue
                if modo == 4:
                    self.replay(p)
                else:
                    self.enviar(p, texto, modo)
                enviados += 1
            if not enviados:
                print("No hay ninguna placa conectada.")

    def cliente_loop(self):
        while self.run:
            for pid, p in self.peers.items():
                # El nodo C siempre intenta conectar a las placas que conoce.
                # Si ambos lados inician a la vez, uno gana y el otro reemplaza su sesion.
                if not p.activo and pid in self.ips:
                    self.conectar(pid)
            time.sleep(4)

    def start(self):
        print(f"=== Nodo C (simulado) {self.id} en {self.ip} ===")
        print(f"Mi huella de clave publica: {huella_pub(self.priv.public_key())}")
        print("Dispositivos autorizados (huella de su clave publica):")
        for pid, p in self.peers.items():
            print(f"  {pid:19s} {huella_pub(p.pub)}")
        print(f"g = {DH_G} | p = primo MODP de 2048 bits (RFC 3526)")
        for t in (self.anunciar_loop, self.escuchar_anuncios, self.servidor_loop, self.cliente_loop):
            threading.Thread(target=t, daemon=True).start()
        self.consola()


def cargar_priv(ruta):
    with open(ruta) as f:
        hexa = f.read().strip()
    if len(hexa) != 64:
        sys.exit(f"{ruta}: la clave privada debe tener 64 caracteres hexadecimales.")
    return ec.derive_private_key(int(hexa, 16), ec.SECP256R1())


def cargar_autorizados(ruta):
    out = {}
    with open(ruta) as f:
        for n, linea in enumerate(f, 1):
            linea = linea.strip()
            if not linea or linea.startswith("#"):
                continue
            pid, _, hexa = linea.partition("=")
            try:
                out[pid.strip()] = ec.EllipticCurvePublicKey.from_encoded_point(
                    ec.SECP256R1(), bytes.fromhex(hexa.strip()))
            except Exception:
                sys.exit(f"{ruta}, linea {n}: clave publica invalida para '{pid.strip()}'.")
    return out


def leer_pubs_hex(keydir):
    """authorized.txt -> dict ID -> clave publica en hex (130 caracteres)."""
    ruta = os.path.join(keydir, "authorized.txt")
    out = {}
    if os.path.exists(ruta):
        with open(ruta) as f:
            for linea in f:
                linea = linea.strip()
                if linea and not linea.startswith("#") and "=" in linea:
                    pid, _, hexa = linea.partition("=")
                    out[pid.strip()] = hexa.strip().upper()
    return out


def escribir_pubs_hex(keydir, pubs):
    os.makedirs(keydir, exist_ok=True)
    with open(os.path.join(keydir, "authorized.txt"), "w") as f:
        f.write("# ID=clave publica (no es secreta)\n")
        for pid in sorted(pubs):
            f.write(f"{pid}={pubs[pid]}\n")


def validar_pub_hex(pid, hexa):
    hexa = hexa.strip().upper()
    if len(hexa) != 130 or not hexa.startswith("04"):
        sys.exit(f"La clave publica de {pid} debe tener 130 caracteres hex y empezar con 04.")
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(hexa))
    except Exception:
        sys.exit(f"La clave publica de {pid} no es un punto valido de la curva P-256 (¿se copio mal?).")
    return hexa


def imprimir_bloque(pubs):
    print("const Autorizado AUTORIZADOS[] = {")
    for pid in sorted(pubs):
        print(f'    {{ "{pid}", "{pubs[pid]}" }},')
    print("};")


def gestionar_claves(args):
    keydir = args.keydir
    pubs = leer_pubs_hex(keydir)
    nuevos = {}
    for pid in (args.genkey or []):
        if not (1 <= len(pid) <= 19):
            sys.exit(f"ID invalido '{pid}' (1 a 19 caracteres).")
        ruta = os.path.join(keydir, pid + ".key")
        if os.path.exists(ruta) and not args.force:
            sys.exit(f"{ruta} ya existe. Si de verdad quieres regenerarla (habra que re-programar la placa y "
                     f"avisar a los demas para que actualicen tu clave publica), usa --force.")
        os.makedirs(keydir, exist_ok=True)
        k = ec.generate_private_key(ec.SECP256R1())
        with open(ruta, "w") as f:
            f.write(k.private_numbers().private_value.to_bytes(32, "big").hex().upper() + "\n")
        pubs[pid] = pub_bytes(k.public_key()).hex().upper()
        nuevos[pid] = (k.private_numbers().private_value.to_bytes(32, "big").hex().upper(), pubs[pid])
    for item in (args.addpub or []):
        pid, _, hexa = item.partition("=")
        pid = pid.strip()
        if not pid or not hexa:
            sys.exit(f"Formato invalido '{item}'. Usa ID=CLAVE_PUBLICA_HEX.")
        hexa = validar_pub_hex(pid, hexa)
        propia = os.path.join(keydir, pid + ".key")
        if os.path.exists(propia):                       # si la privada es mia, la publica debe coincidir
            if pub_bytes(cargar_priv(propia).public_key()).hex().upper() != hexa:
                sys.exit(f"{pid}: la clave publica no corresponde a tu keys/{pid}.key.")
        pubs[pid] = hexa
        print(f"Agregada la clave publica de {pid}.")
    escribir_pubs_hex(keydir, pubs)

    if nuevos:
        print(f"\nClaves generadas en '{keydir}/'. Las .key son PRIVADAS: no las subas a GitHub ni las compartas.\n")
        for pid, (priv, pub) in nuevos.items():
            print(f"=== {pid} ===")
            print(f'  Privada (SECRETA, solo para el dispositivo {pid}):')
            print(f'    const char* MY_PRIV_HEX = "{priv}";')
            print(f"  Publica: comparte SOLO esta linea con los demas; ellos corren:")
            print(f"    python nodo_pc.py --addpub {pid}={pub}\n")
    print("=== Bloque AUTORIZADOS para el .ino (publico; debe ser IGUAL en todas las placas) ===\n")
    imprimir_bloque(pubs)
    esperados = {"ESP32_Bryan", "ESP32_Christopher", "ESP32_Demian"}
    faltan = sorted(esperados - set(pubs))
    if faltan:
        print(f"\nAun faltan las claves publicas de: {', '.join(faltan)}. Pidesela a su dueño y agregala con --addpub.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--genkey", nargs="+", metavar="ID",
                    help="genera TU par de claves (solo los IDs que sean tuyos) y sale. Ej: --genkey ESP32_Bryan ESP32_Demian")
    ap.add_argument("--addpub", action="append", metavar="ID=PUBLICA_HEX",
                    help="agrega la clave PUBLICA de otro dispositivo (repetible)")
    ap.add_argument("--block", action="store_true", help="imprime el bloque AUTORIZADOS para el .ino y sale")
    ap.add_argument("--force", action="store_true", help="con --genkey: sobrescribe claves existentes")
    ap.add_argument("--id", default="ESP32_Demian")
    ap.add_argument("--ip", help="IPv4 WiFi de esta laptop")
    ap.add_argument("--keydir", default="keys", help="carpeta con <ID>.key y authorized.txt (por defecto: keys)")
    ap.add_argument("--peer", action="append", default=[], metavar="ID=IP",
                    help="fija la IP de una placa a mano (ej: --peer ESP32_Bryan=192.168.1.32). Repetible.")
    ap.add_argument("--quiet", action="store_true", help="menos salida (sin volcados hex)")
    args = ap.parse_args()
    if args.genkey or args.addpub or args.block:
        gestionar_claves(args)
        return
    if not args.ip:
        ap.error("falta --ip (o usa --genkey / --addpub / --block para gestionar las claves)")
    priv = cargar_priv(os.path.join(args.keydir, args.id + ".key"))
    autorizados = cargar_autorizados(os.path.join(args.keydir, "authorized.txt"))
    if args.id not in autorizados:
        sys.exit(f"{args.id} no esta en {args.keydir}/authorized.txt.")
    if pub_bytes(priv.public_key()) != pub_bytes(autorizados[args.id]):
        sys.exit(f"keys/{args.id}.key no corresponde a la clave publica de {args.id} en authorized.txt.")
    nodo = NodoC(args.id, args.ip, priv, autorizados, verbose=not args.quiet)
    for item in args.peer:
        if "=" in item:
            pid, ip = item.split("=", 1)
            if pid in nodo.peers:
                nodo.ips[pid] = ip
                print(f"[FIJADA] {pid} en {ip} (manual)")
    nodo.start()


if __name__ == "__main__":
    main()
