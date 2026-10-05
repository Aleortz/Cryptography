// =====================================================================
//  Proyecto 1 - Secure Wireless Messaging for IoT Devices
//  Nodo peer-to-peer (ESP32), sin servidor. Un solo archivo.
//
//  Criptografia (toda con mbedTLS, incluida en el core ESP32 de Arduino):
//    - Diffie-Hellman clasico sobre el grupo MODP de 2048 bits del RFC 3526
//      (g y p publicos y fijos). Claves efimeras nuevas en cada sesion.
//    - Autenticacion mutua con FIRMAS ECDSA P-256 sobre el transcript completo
//      (IDs, nonces, claves publicas DH). Cada placa tiene su PROPIA clave
//      privada y la lista de autorizados trae la clave PUBLICA de cada una.
//      Robar una placa permite suplantar solo a esa placa.
//    - HKDF-SHA256 -> clave AES-256 raiz por direccion + Session ID.
//    - Cadena de claves por mensaje (KDF chain). El estado CK_n avanza con
//      CK_(n+1) = HKDF(CK_n,"P1-CHAIN") y cada mensaje se cifra con su propia
//      clave MK_n = HKDF(CK_n,"P1-MSG"). CK_n se borra tras avanzar. Conocer
//      MK_n no revela CK_n ni ninguna otra MK; conocer CK_n no revela claves
//      de mensajes anteriores (forward secrecy por mensaje).
//    - Mensajes con AES-256-GCM, la cabecera completa como AAD.
//  El monitor imprime los parametros (g, p, privada, publica, secreto,
//  claves de sesion) y, en cada mensaje, el plaintext, el ciphertext en
//  hex y el plaintext recuperado. Las lineas largas se imprimen por bloques.
// =====================================================================

// ======================= CONFIGURACIÓN (editar) =======================
const char* WIFI_SSID = "PLUS DANY";      // el ESP32 solo funciona en 2.4 GHz
const char* WIFI_PASS = "dany2027";
const char* MY_ID     = "ESP32_Bryan";        // DISTINTO en cada placa (máx. 19 caracteres)

// Clave PRIVADA de ESTA placa (ECDSA P-256): 64 caracteres hexadecimales. SECRETA:
// va solo en esta placa. Cada dueño genera SOLO la suya, en su PC:
//     python nodo_pc.py --genkey <TU_ID>
const char* MY_PRIV_HEX = "0B9C73E0AEBD362700A05CEB7956F7B16ABFCB4BF25FE727B3DC46ACCEF95B0E";

// Dispositivos autorizados: ID + CLAVE PUBLICA (130 caracteres hex, empieza con 04).
// La clave publica NO es secreta. Esta lista es la MISMA en todas las placas
// (las claves publicas de los demas se agregan con "python nodo_pc.py --addpub ID=..."
//  y "python nodo_pc.py --block" imprime el bloque listo para pegar).
struct Autorizado { const char* id; const char* pub_hex; };
const Autorizado AUTORIZADOS[] = {
    { "ESP32_Bryan", "040C05F16FE9034654E8FC57B9DA273C938A2CE1C192909F6808FFF50453E75C2832C29DE3B4E64F2576FB4EF8C597E7FF3C12E20AFF880B45031AD60A73D2B6FD" },
    { "ESP32_Demian", "04E3C2BE2259D2A909E5EC0FB852915B64DAD99F800A3A50AB4AA3C94A9685E9502C6BA6B6FC0C0AC50F244278AD8A3B1504322475B5985301E72E904A38836F04" },
     { "ESP32_Christopher", "048B0A220E01E9EF6DEAFA17E37951F92D39EDE84A5EFD1C5422670DAF28863A6B5BAFD8C72140413A9F5353B49933D22A803139E4D8557C2A255DED673C7D81F8" },
};

// Verbosidad: true imprime g, p, claves y el detalle de cada mensaje
const bool VERBOSE = true;

#include <WiFi.h>
#include <WiFiUdp.h>
#include "mbedtls/bignum.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/md.h"
#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#if __has_include(<esp_random.h>)
  #include <esp_random.h>
#endif

// --- Grupo Diffie-Hellman: MODP de 2048 bits, RFC 3526 (g y p publicos) ---
const char* DH_P_HEX =
"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
"020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
"4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
"98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
"9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
"3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
const int DH_G = 2;
const size_t DH_LEN = 256;              // 2048 bits = 256 bytes
const size_t DH_PRIV_BITS = 256;        // exponente privado de 256 bits

// --- Parámetros del protocolo ---
const uint16_t PUERTO = 8080;
const uint16_t PUERTO_DESC = 8081;
const uint16_t MAX_CIPHER_LEN = 1024;
const unsigned long TIMEOUT_MS = 15000; // el DH de 2048 bits en el otro extremo tarda segundos
const unsigned long REINTENTO_MS = 4000;
const unsigned long ANUNCIO_MS = 2000;
const uint8_t FRAME_DATA = 0x01;        // [0x01][PacketHeader][C][TAG]
const uint8_t FRAME_ACK  = 0x02;        // [0x02][Ack]
const char MAGIC[4] = { 'P', '1', 'v', '4' };
const char* MENSAJE_PRUEBA = "Temp: 24.5C | Hum: 60% | Nodo Activo";
const int MAX_PEERS = sizeof(AUTORIZADOS) / sizeof(AUTORIZADOS[0]);
const int SERIAL_CHUNK = 64;            // ancho de bloque para imprimir líneas largas

// --- Descubrimiento ---
struct __attribute__((packed)) Anuncio {
    char magic[4];
    char id[20];
};

// --- Mensajes del handshake ---
struct __attribute__((packed)) Hello {        // HS1: iniciador -> respondedor
    char magic[4];
    char id[20];
    uint8_t nonce[16];
    uint8_t dh_pub[DH_LEN];                    // clave pública DH (g^priv mod p)
};
struct __attribute__((packed)) HelloReply {   // HS2: respondedor -> iniciador
    uint8_t status;                           // 1 = continuar, 0 = ID no autorizado
    char id[20];
    uint8_t nonce[16];
    uint8_t dh_pub[DH_LEN];
    uint8_t sig[64];                          // ECDSA(r||s) del respondedor sobre SHA256("P1-RESP" || T)
};
struct __attribute__((packed)) Finish {       // HS3: iniciador -> respondedor
    uint8_t sig[64];                          // ECDSA(r||s) del iniciador sobre SHA256("P1-INIT" || T)
};                                            // HS4: 1 byte, 1 = sesión aceptada

// --- Mensajes de aplicación ---
// ID_S || SID || SEQ || N || Len  (toda la cabecera va como AAD en GCM)
struct __attribute__((packed)) PacketHeader {
    char sender_id[20];
    uint32_t session_id;
    uint32_t seq_num;
    uint8_t nonce[12];
    uint16_t cipher_len;
};
struct __attribute__((packed)) Ack {
    uint32_t seq_num;
    uint8_t status;
};

const size_t MAX_FRAME = 1 + sizeof(PacketHeader) + MAX_CIPHER_LEN + 16;

// --- Estado de cada peer ---
struct Peer {
    const char* id;
    uint8_t pub[65];               // clave publica ECDSA grabada para este ID (04||X||Y)
    bool tiene_pub;                // false si la clave publica de la lista no es valida
    char ip[16];
    WiFiClient sock;
    bool activo;
    uint8_t k_tx[32];              // CK de envio: estado de la cadena (avanza con cada mensaje)
    uint8_t k_rx[32];              // CK de recepcion: estado de la cadena del peer
    uint32_t sid;
    uint32_t tx_seq;
    uint32_t rx_last;
    unsigned long ultimo_intento;
    bool pendiente;
    uint32_t pend_seq;
    unsigned long pend_t0;
    uint8_t pend_frame[MAX_FRAME];
    size_t pend_len;
    uint8_t ultimo_frame[MAX_FRAME];
    size_t ultimo_len;
};

Peer peers[MAX_PEERS];
WiFiServer servidor(PUERTO);
WiFiUDP udp;
mbedtls_mpi DH_P, DH_G_mpi;
mbedtls_ecp_group ECP_GRP;     // curva P-256 (para las firmas)
mbedtls_mpi MY_D;              // mi clave privada de identidad
unsigned long ultimo_anuncio = 0;

char linea[1001];
size_t linea_len = 0;
unsigned long ultimo_char = 0;

// IMPORTANTE: esta macro se expande a una función. El Arduino IDE inserta los
// prototipos antes de la primera función del archivo, así que debe ir DESPUÉS
// de todos los struct (si no: "'Hello' does not name a type").
#ifdef SET_LOOP_TASK_STACK_SIZE
SET_LOOP_TASK_STACK_SIZE(20 * 1024);   // margen para la exponenciación modular de 2048 bits
#endif

// =====================================================================
//  Impresión (con corte por bloques para no exceder el buffer del Serial)
// =====================================================================
// Imprime texto largo en bloques de SERIAL_CHUNK, con un pequeño respiro para
// que el buffer de transmisión del Serial se vacíe y no se pierdan caracteres.
void printChunked(const char* etiqueta, const char* texto, size_t len) {
    Serial.printf("%s (%u bytes):\n", etiqueta, (unsigned)len);
    for (size_t i = 0; i < len; i += SERIAL_CHUNK) {
        size_t n = (len - i < (size_t)SERIAL_CHUNK) ? len - i : SERIAL_CHUNK;
        Serial.write((const uint8_t*)texto + i, n);
        Serial.println();
        Serial.flush();
    }
}

// Imprime bytes en hexadecimal, en bloques (cada byte ocupa 2 caracteres)
void printHex(const char* etiqueta, const uint8_t* buf, size_t len) {
    Serial.printf("%s (%u bytes):\n", etiqueta, (unsigned)len);
    const int por_linea = SERIAL_CHUNK / 2;
    for (size_t i = 0; i < len; i += por_linea) {
        char fila[por_linea * 2 + 1];
        size_t p = 0;
        for (size_t j = i; j < len && j < i + por_linea; j++)
            p += sprintf(fila + p, "%02X", buf[j]);
        Serial.println(fila);
        Serial.flush();
    }
}

// =====================================================================
//  Primitivas criptográficas (todas de mbedTLS)
// =====================================================================
static int rng(void*, unsigned char* out, size_t len) {
    esp_fill_random(out, len);
    return 0;
}

void sha256(const uint8_t* in, size_t len, uint8_t out[32]) {
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), in, len, out);
}

// Firma/verificacion ECDSA P-256 del transcript. Lo que se firma es
// SHA256(etiqueta || T): la etiqueta ("P1-RESP" / "P1-INIT") evita reutilizar una
// firma en el otro sentido, y T ata la firma a ESTE handshake (IDs, nonces, DH).
static void hashTranscript(const char* etiqueta, const uint8_t T[32], uint8_t h[32]) {
    uint8_t buf[7 + 32];
    memcpy(buf, etiqueta, 7);
    memcpy(buf + 7, T, 32);
    sha256(buf, sizeof(buf), h);
}

bool firmarTranscript(const char* etiqueta, const uint8_t T[32], uint8_t sig[64]) {
    uint8_t h[32];
    hashTranscript(etiqueta, T, h);
    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    bool ok = mbedtls_ecdsa_sign(&ECP_GRP, &r, &s, &MY_D, h, sizeof(h), rng, NULL) == 0 &&
              mbedtls_mpi_write_binary(&r, sig, 32) == 0 &&
              mbedtls_mpi_write_binary(&s, sig + 32, 32) == 0;
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    return ok;
}

// Verifica con la clave publica GRABADA en la lista de autorizados, nunca con una
// recibida por la red.
bool verificarFirma(const uint8_t pub[65], const char* etiqueta, const uint8_t T[32], const uint8_t sig[64]) {
    uint8_t h[32];
    hashTranscript(etiqueta, T, h);
    mbedtls_ecp_point Q;
    mbedtls_mpi r, s;
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    bool ok = mbedtls_ecp_point_read_binary(&ECP_GRP, &Q, pub, 65) == 0 &&
              mbedtls_mpi_read_binary(&r, sig, 32) == 0 &&
              mbedtls_mpi_read_binary(&s, sig + 32, 32) == 0 &&
              mbedtls_ecdsa_verify(&ECP_GRP, h, sizeof(h), &Q, &r, &s) == 0;
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    return ok;
}

bool hkdf(const uint8_t* salt, size_t salt_len, const uint8_t* ikm, size_t ikm_len,
          const uint8_t* info, size_t info_len, uint8_t* okm, size_t okm_len) {
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
#if defined(MBEDTLS_HKDF_C) && !defined(FORZAR_HKDF_MANUAL)
    return mbedtls_hkdf(md, salt, salt_len, ikm, ikm_len, info, info_len, okm, okm_len) == 0;
#else
    uint8_t prk[32], t[32];
    if (mbedtls_md_hmac(md, salt, salt_len, ikm, ikm_len, prk) != 0) return false;
    size_t hecho = 0;
    uint8_t contador = 1, t_len = 0;
    while (hecho < okm_len) {
        mbedtls_md_context_t ctx;
        mbedtls_md_init(&ctx);
        bool ok = mbedtls_md_setup(&ctx, md, 1) == 0 &&
                  mbedtls_md_hmac_starts(&ctx, prk, 32) == 0 &&
                  mbedtls_md_hmac_update(&ctx, t, t_len) == 0 &&
                  mbedtls_md_hmac_update(&ctx, info, info_len) == 0 &&
                  mbedtls_md_hmac_update(&ctx, &contador, 1) == 0 &&
                  mbedtls_md_hmac_finish(&ctx, t) == 0;
        mbedtls_md_free(&ctx);
        if (!ok) return false;
        size_t n = (okm_len - hecho < 32) ? okm_len - hecho : 32;
        memcpy(okm + hecho, t, n);
        hecho += n;
        t_len = 32;
        contador++;
    }
    return true;
#endif
}

// Cadena de claves. CK es el estado de la cadena; MK es la clave de UN solo mensaje.
//   MK_n     = HKDF(CK_n, "P1-MSG")     (se usa para cifrar/descifrar el mensaje n)
//   CK_(n+1) = HKDF(CK_n, "P1-CHAIN")   (el estado avanza; CK_n se borra)
// Ambas son unidireccionales: MK_n no permite recuperar CK_n ni otras MK.
void claveDeMensaje(const uint8_t ck[32], uint8_t mk[32]) {
    const uint8_t cero[1] = { 0 };
    hkdf(cero, 0, ck, 32, (const uint8_t*)"P1-MSG", 6, mk, 32);
}

void avanzarCadena(uint8_t ck[32]) {
    uint8_t nueva[32];
    const uint8_t cero[1] = { 0 };
    hkdf(cero, 0, ck, 32, (const uint8_t*)"P1-CHAIN", 8, nueva, 32);
    memcpy(ck, nueva, 32);
    memset(nueva, 0, sizeof(nueva));
}

// Genera la pareja DH: priv aleatorio de 256 bits, pub = g^priv mod p (en DH_LEN bytes)
bool generarDH(mbedtls_mpi* priv, uint8_t pub[DH_LEN]) {
    mbedtls_mpi P;
    mbedtls_mpi_init(&P);
    bool ok = mbedtls_mpi_fill_random(priv, DH_PRIV_BITS / 8, rng, NULL) == 0 &&
              mbedtls_mpi_exp_mod(&P, &DH_G_mpi, priv, &DH_P, NULL) == 0 &&
              mbedtls_mpi_write_binary(&P, pub, DH_LEN) == 0;
    mbedtls_mpi_free(&P);
    return ok;
}

// Secreto compartido z = peer_pub^priv mod p
bool secretoDH(const mbedtls_mpi* priv, const uint8_t peer_pub[DH_LEN], uint8_t z[DH_LEN]) {
    mbedtls_mpi Pub, Z;
    mbedtls_mpi_init(&Pub);
    mbedtls_mpi_init(&Z);
    // 2 <= peer_pub <= p-2 (rechaza 0, 1, p-1: valores degenerados)
    mbedtls_mpi dos, pmenos1;
    mbedtls_mpi_init(&dos); mbedtls_mpi_init(&pmenos1);
    mbedtls_mpi_lset(&dos, 2);
    mbedtls_mpi_sub_int(&pmenos1, &DH_P, 1);
    bool ok = mbedtls_mpi_read_binary(&Pub, peer_pub, DH_LEN) == 0 &&
              mbedtls_mpi_cmp_mpi(&Pub, &dos) >= 0 &&
              mbedtls_mpi_cmp_mpi(&Pub, &pmenos1) < 0 &&
              mbedtls_mpi_exp_mod(&Z, &Pub, priv, &DH_P, NULL) == 0 &&
              mbedtls_mpi_write_binary(&Z, z, DH_LEN) == 0;
    mbedtls_mpi_free(&Pub); mbedtls_mpi_free(&Z);
    mbedtls_mpi_free(&dos); mbedtls_mpi_free(&pmenos1);
    return ok;
}

// T = SHA256(Hello || id_R || nonce_R || dh_pub_R)
void transcript(const Hello& h, const HelloReply& r, uint8_t T[32]) {
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, md, 0);
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, (const uint8_t*)&h, sizeof(Hello));
    mbedtls_md_update(&ctx, (const uint8_t*)r.id, 20);
    mbedtls_md_update(&ctx, r.nonce, 16);
    mbedtls_md_update(&ctx, r.dh_pub, DH_LEN);
    mbedtls_md_finish(&ctx, T);
    mbedtls_md_free(&ctx);
}

// okm = k_iniciador->respondedor (32) || k_respondedor->iniciador (32) || SID (4)
bool derivarClaves(const uint8_t* z, const Hello& h, const HelloReply& r, const uint8_t T[32], uint8_t okm[68]) {
    uint8_t salt[32], info[7 + 32];
    memcpy(salt, h.nonce, 16);
    memcpy(salt + 16, r.nonce, 16);
    memcpy(info, "P1-KEYS", 7);
    memcpy(info + 7, T, 32);
    return hkdf(salt, 32, z, DH_LEN, info, sizeof(info), okm, 68);
}

void imprimirParametrosDH() {
    if (!VERBOSE) return;
    uint8_t p_bin[DH_LEN];
    mbedtls_mpi_write_binary(&DH_P, p_bin, DH_LEN);
    Serial.println("\n--- Parametros Diffie-Hellman publicos (compartidos) ---");
    Serial.printf("Generador g = %d\n", DH_G);
    printHex("Modulo primo p (2048 bits)", p_bin, DH_LEN);
    Serial.println("--------------------------------------------------------");
}

// =====================================================================
//  Utilidades
// =====================================================================
bool readExact(WiFiClient& cli, uint8_t* buf, size_t len) {
    size_t leidos = 0;
    unsigned long inicio = millis();
    while (leidos < len && millis() - inicio < TIMEOUT_MS) {
        if (cli.available()) {
            int n = cli.read(buf + leidos, len - leidos);
            if (n > 0) leidos += n;
        } else if (!cli.connected()) {
            break;
        } else {
            delay(1);
        }
    }
    return leidos == len;
}

int buscarPeer(const char* id) {
    for (int i = 0; i < MAX_PEERS; i++)
        if (strcmp(peers[i].id, id) == 0) return i;
    return -1;
}

bool esYo(const Peer& p) { return strcmp(p.id, MY_ID) == 0; }

int hexNibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Convierte "A1B2..." en n bytes. Exige exactamente 2*n caracteres hexadecimales.
bool hexABytes(const char* hex, uint8_t* out, size_t n) {
    if (strlen(hex) != 2 * n) return false;
    for (size_t i = 0; i < n; i++) {
        int a = hexNibble(hex[2 * i]), b = hexNibble(hex[2 * i + 1]);
        if (a < 0 || b < 0) return false;
        out[i] = (a << 4) | b;
    }
    return true;
}

// Huella corta (4 bytes del SHA-256) de una clave publica, para compararlas a simple vista
void huellaPub(const uint8_t pub[65], char out[9]) {
    uint8_t h[32];
    sha256(pub, 65, h);
    snprintf(out, 9, "%02X%02X%02X%02X", h[0], h[1], h[2], h[3]);
}

// Una clave publica es valida si es un punto real de la curva P-256
bool clavePublicaValida(const uint8_t pub[65]) {
    mbedtls_ecp_point Q;
    mbedtls_ecp_point_init(&Q);
    bool ok = mbedtls_ecp_point_read_binary(&ECP_GRP, &Q, pub, 65) == 0 &&
              mbedtls_ecp_check_pubkey(&ECP_GRP, &Q) == 0;
    mbedtls_ecp_point_free(&Q);
    return ok;
}

void cerrarSesion(Peer& p, const char* motivo) {
    if (p.activo) Serial.printf("[-] Sesion con %s cerrada: %s\n", p.id, motivo);
    p.sock.stop();
    p.activo = false;
    p.pendiente = false;
}

void establecerSesion(Peer& p, WiFiClient& c, const uint8_t okm[68], const uint8_t* z,
                      const uint8_t pub_propia[DH_LEN], bool soy_iniciador, unsigned long t_hs) {
    if (p.activo) p.sock.stop();
    p.sock = c;
    p.sock.setNoDelay(true);
    memcpy(soy_iniciador ? p.k_tx : p.k_rx, okm, 32);
    memcpy(soy_iniciador ? p.k_rx : p.k_tx, okm + 32, 32);
    memcpy(&p.sid, okm + 64, 4);
    p.tx_seq = 0;
    p.rx_last = 0;
    p.pendiente = false;
    p.ultimo_len = 0;
    p.activo = true;

    Serial.printf("\n==== Clave de sesion establecida con %s ====\n", p.id);
    Serial.printf("Rol: %s | SID: 0x%08X | Handshake: %lu ms\n",
                  soy_iniciador ? "iniciador" : "respondedor", p.sid, t_hs);
    if (VERBOSE) {
        printHex("Mi clave publica DH", pub_propia, DH_LEN);
        printHex("Secreto compartido DH (z = pub_peer^priv mod p)", z, DH_LEN);
        printHex("Cadena inicial -> envio a este peer (CK_tx)", p.k_tx, 32);
        printHex("Cadena inicial <- recibo de este peer (CK_rx)", p.k_rx, 32);
    }
    Serial.println("=============================================\n");
}

// =====================================================================
//  Descubrimiento por UDP broadcast
// =====================================================================
void anunciarme() {
    Anuncio a;
    memset(&a, 0, sizeof(a));
    memcpy(a.magic, MAGIC, 4);
    strncpy(a.id, MY_ID, sizeof(a.id) - 1);
    udp.beginPacket(WiFi.broadcastIP(), PUERTO_DESC);
    udp.write((const uint8_t*)&a, sizeof(a));
    udp.endPacket();
}

void escucharAnuncios() {
    while (udp.parsePacket() > 0) {
        Anuncio a;
        int n = udp.read((uint8_t*)&a, sizeof(a));
        if (n != sizeof(a) || memcmp(a.magic, MAGIC, 4) != 0) continue;
        char id[21] = {0};
        memcpy(id, a.id, 20);
        int idx = buscarPeer(id);
        if (idx < 0 || esYo(peers[idx])) continue;
        String ip = udp.remoteIP().toString();
        if (strcmp(peers[idx].ip, ip.c_str()) != 0) {
            strncpy(peers[idx].ip, ip.c_str(), sizeof(peers[idx].ip) - 1);
            Serial.printf("[DESCUBIERTA] %s en %s\n", id, peers[idx].ip);
        }
    }
}

// =====================================================================
//  Handshake
// =====================================================================
void conectarA(Peer& p) {
    p.ultimo_intento = millis();
    WiFiClient c;
    if (!c.connect(p.ip, PUERTO, 2000)) return;
    c.setNoDelay(true);
    unsigned long t0 = millis();
    Serial.printf("\n[..] Iniciando handshake Diffie-Hellman con %s (puede tardar unos segundos)...\n", p.id);

    Hello h;
    memset(&h, 0, sizeof(h));
    memcpy(h.magic, MAGIC, 4);
    strncpy(h.id, MY_ID, sizeof(h.id) - 1);
    rng(NULL, h.nonce, sizeof(h.nonce));
    mbedtls_mpi priv;
    mbedtls_mpi_init(&priv);
    const char* error = nullptr;
    HelloReply r;
    Finish f;
    uint8_t T[32], okm[68], resultado = 0;
    static uint8_t z[DH_LEN];

    if (!generarDH(&priv, h.dh_pub)) error = "no se pudo generar la clave DH";
    else {
        if (VERBOSE) {
            Serial.printf("Mi clave privada DH (%u bits, se mantiene en secreto):\n", (unsigned)DH_PRIV_BITS);
            uint8_t pb[DH_PRIV_BITS / 8];
            mbedtls_mpi_write_binary(&priv, pb, sizeof(pb));
            printHex("  priv", pb, sizeof(pb));
        }
        if (c.write((const uint8_t*)&h, sizeof(h)) != sizeof(h)) error = "fallo al enviar Hello";
        else if (!readExact(c, (uint8_t*)&r, sizeof(r))) error = "no respondio al handshake";
        else if (r.status != 1) error = "me rechazo (mi ID no esta en su lista de autorizados)";
        else if (strncmp(r.id, p.id, sizeof(r.id)) != 0) error = "respondio con otra identidad";
        else {
            transcript(h, r, T);
            if (!verificarFirma(p.pub, "P1-RESP", T, r.sig)) {
                Serial.printf("[ALERTA] %s NO demostro ser quien dice (firma invalida): posible suplantacion o MITM.\n", p.id);
                error = "firma del respondedor invalida";
            } else if (!firmarTranscript("P1-INIT", T, f.sig)) {
                error = "no se pudo firmar";
            } else {
                if (c.write((const uint8_t*)&f, sizeof(f)) != sizeof(f)) error = "fallo al enviar Finish";
                else if (!readExact(c, &resultado, 1) || resultado != 1) error = "rechazo mi firma (¿mi clave publica no coincide en su lista?)";
                else if (!secretoDH(&priv, r.dh_pub, z) || !derivarClaves(z, h, r, T, okm)) error = "fallo al derivar claves";
            }
        }
    }
    mbedtls_mpi_free(&priv);

    if (error) {
        Serial.printf("[X] Handshake con %s fallido: %s\n", p.id, error);
        c.stop();
        return;
    }
    establecerSesion(p, c, okm, z, h.dh_pub, true, millis() - t0);
    memset(z, 0, sizeof(z));
    memset(okm, 0, sizeof(okm));
}

void atenderEntrante(WiFiClient& c) {
    String ip = c.remoteIP().toString();
    unsigned long t0 = millis();
    Hello h;
    if (!readExact(c, (uint8_t*)&h, sizeof(h))) {
        Serial.printf("[ALERTA] Conexion desde %s sin handshake completo. Descartada.\n", ip.c_str());
        c.stop();
        return;
    }
    if (memcmp(h.magic, MAGIC, 4) != 0) {
        Serial.printf("[ALERTA] Datos sin protocolo valido desde %s (paquete forjado/inyectado). Descartado.\n", ip.c_str());
        c.stop();
        return;
    }
    char id[21] = {0};
    memcpy(id, h.id, 20);
    int idx = buscarPeer(id);

    HelloReply r;
    memset(&r, 0, sizeof(r));
    if (idx < 0 || esYo(peers[idx]) || !peers[idx].tiene_pub) {
        Serial.printf("[ALERTA] Intento de acceso desde dispositivo NO AUTORIZADO '%s' (%s). Rechazado.\n", id, ip.c_str());
        c.write((const uint8_t*)&r, sizeof(r));
        c.stop();
        return;
    }
    Peer& p = peers[idx];
    Serial.printf("\n[..] Handshake Diffie-Hellman entrante de %s (%s)...\n", id, ip.c_str());

    r.status = 1;
    strncpy(r.id, MY_ID, sizeof(r.id) - 1);
    rng(NULL, r.nonce, sizeof(r.nonce));
    mbedtls_mpi priv;
    mbedtls_mpi_init(&priv);
    uint8_t T[32], okm[68], resultado = 0;
    static uint8_t z[DH_LEN];
    Finish f;
    const char* error = nullptr;

    if (!generarDH(&priv, r.dh_pub)) error = "no se pudo generar la clave DH";
    else {
        transcript(h, r, T);
        if (!firmarTranscript("P1-RESP", T, r.sig)) error = "no se pudo firmar";
        else if (c.write((const uint8_t*)&r, sizeof(r)) != sizeof(r)) error = "fallo al enviar HelloReply";
        else if (!readExact(c, (uint8_t*)&f, sizeof(f))) {
            Serial.printf("[ALERTA] '%s' abandono el handshake sin autenticarse.\n", id);
            error = "no envio su autenticacion";
        } else {
            if (!verificarFirma(p.pub, "P1-INIT", T, f.sig)) {
                Serial.printf("[ALERTA] Intento de manipulacion/suplantacion detectado desde '%s' (%s): firma invalida, no posee la clave privada de ese dispositivo. Rechazado.\n",
                              id, ip.c_str());
                error = "firma del iniciador invalida";
            } else if (!secretoDH(&priv, h.dh_pub, z) || !derivarClaves(z, h, r, T, okm)) {
                error = "fallo al derivar claves";
            }
        }
    }
    mbedtls_mpi_free(&priv);

    resultado = (error == nullptr) ? 1 : 0;
    c.write(&resultado, 1);
    if (error) {
        Serial.printf("[X] Handshake entrante de '%s' fallido: %s\n", id, error);
        c.stop();
        return;
    }
    strncpy(p.ip, ip.c_str(), sizeof(p.ip) - 1);
    establecerSesion(p, c, okm, z, r.dh_pub, false, millis() - t0);
    memset(z, 0, sizeof(z));
    memset(okm, 0, sizeof(okm));
}

// =====================================================================
//  Envío de mensajes y pruebas de seguridad
// =====================================================================
void enviarA(Peer& p, const char* texto, int modo) {
    size_t len = strlen(texto);
    if (len > MAX_CIPHER_LEN) len = MAX_CIPHER_LEN;

    uint8_t frame[MAX_FRAME];
    frame[0] = FRAME_DATA;
    PacketHeader hdr;
    memset(&hdr, 0, sizeof(hdr));
    strncpy(hdr.sender_id, MY_ID, sizeof(hdr.sender_id) - 1);
    hdr.session_id = p.sid;
    hdr.seq_num = ++p.tx_seq;
    rng(NULL, hdr.nonce, 8);
    memcpy(hdr.nonce + 8, &hdr.seq_num, 4);
    hdr.cipher_len = len;

    uint8_t* ct = frame + 1 + sizeof(PacketHeader);
    uint8_t* tag = ct + len;

    uint8_t mk[32];
    claveDeMensaje(p.k_tx, mk);            // clave de ESTE mensaje, derivada de la cadena
    uint8_t clave_falsa[32];
    const uint8_t* clave = mk;
    if (modo == 6) {
        rng(NULL, clave_falsa, sizeof(clave_falsa));
        clave = clave_falsa;
        Serial.printf("[TEST -> %s] Inyectando paquete forjado (clave que no es la de la sesion)\n", p.id);
    }

    Serial.printf("\n>>> ENVIANDO a %s (SEQ %u) <<<\n", p.id, hdr.seq_num);
    if (VERBOSE) {
        printChunked("Texto plano (plaintext)", texto, len);
        printHex("Estado de la cadena (CK_tx)", p.k_tx, 32);
        printHex("Clave de ESTE mensaje (MK = HKDF(CK,\"P1-MSG\"))", clave, 32);
    }

    unsigned long t0 = micros();
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, clave, 256);
    mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, len, hdr.nonce, 12,
                              (const uint8_t*)&hdr, sizeof(hdr), (const uint8_t*)texto, ct, 16, tag);
    mbedtls_gcm_free(&gcm);
    unsigned long t_enc = micros() - t0;

    if (modo == 2) { ct[0] ^= 0xFF;  Serial.printf("[TEST -> %s] Alterando 1 byte del ciphertext\n", p.id); }
    if (modo == 3) { tag[0] ^= 0xFF; Serial.printf("[TEST -> %s] Alterando 1 byte del TAG\n", p.id); }
    if (modo == 5) {
        memset(hdr.sender_id, 0, sizeof(hdr.sender_id));
        strncpy(hdr.sender_id, "ESP32_Intruso", sizeof(hdr.sender_id) - 1);
        Serial.printf("[TEST -> %s] Falsificando el remitente (ID_S)\n", p.id);
    }
    memcpy(frame + 1, &hdr, sizeof(hdr));
    size_t total = 1 + sizeof(PacketHeader) + len + 16;

    if (VERBOSE) {
        printHex("Texto cifrado (ciphertext que viaja por la red)", ct, len);
        printHex("TAG de autenticacion GCM", tag, 16);
    }

    memcpy(p.pend_frame, frame, total);
    p.pend_len = total;
    p.pend_seq = hdr.seq_num;
    p.pendiente = true;
    p.pend_t0 = micros();
    p.sock.write(frame, total);

    Serial.printf("Plaintext: %u B | Paquete: %u B (+%u B overhead) | Cifrado: %lu us\n",
                  (unsigned)len, (unsigned)(total - 1), (unsigned)(total - 1 - len), t_enc);

    // La cadena avanza: CK_(n+1) = HKDF(CK_n, "P1-CHAIN"). CK_n se borra.
    memset(mk, 0, sizeof(mk));
    if (modo != 6) {
        avanzarCadena(p.k_tx);
        if (VERBOSE) {
            Serial.printf("[CADENA] Estado avanzado al mensaje %u (CK_n anterior borrada).\n", hdr.seq_num + 1);
            printHex("Nuevo CK_tx", p.k_tx, 32);
        }
    }
}

void probarReplay(Peer& p) {
    if (p.ultimo_len == 0) {
        Serial.printf("[TEST -> %s] Primero envia un mensaje normal para tener un paquete aceptado.\n", p.id);
        return;
    }
    PacketHeader hdr;
    memcpy(&hdr, p.ultimo_frame + 1, sizeof(hdr));
    Serial.printf("\n[TEST -> %s] REPLAY: retransmitiendo el paquete del SEQ %u, identico byte por byte\n", p.id, hdr.seq_num);
    if (VERBOSE) printHex("Paquete retransmitido", p.ultimo_frame, p.ultimo_len);
    memcpy(p.pend_frame, p.ultimo_frame, p.ultimo_len);
    p.pend_len = p.ultimo_len;
    p.pend_seq = hdr.seq_num;
    p.pendiente = true;
    p.pend_t0 = micros();
    p.sock.write(p.ultimo_frame, p.ultimo_len);
}

// =====================================================================
//  Recepción
// =====================================================================
void recibirData(Peer& p) {
    static uint8_t ct[MAX_CIPHER_LEN], pt[MAX_CIPHER_LEN + 1];
    PacketHeader hdr;
    uint8_t tag[16];
    if (!readExact(p.sock, (uint8_t*)&hdr, sizeof(hdr))) { cerrarSesion(p, "paquete incompleto"); return; }
    if (hdr.cipher_len > MAX_CIPHER_LEN) {
        Serial.printf("[ALERTA] %s envio una longitud invalida (%u B).\n", p.id, hdr.cipher_len);
        cerrarSesion(p, "longitud invalida");
        return;
    }
    if (!readExact(p.sock, ct, hdr.cipher_len) || !readExact(p.sock, tag, 16)) {
        cerrarSesion(p, "paquete incompleto");
        return;
    }

    char remitente[21] = {0};
    memcpy(remitente, hdr.sender_id, 20);
    uint8_t mk[32];
    claveDeMensaje(p.k_rx, mk);            // clave que corresponde al siguiente mensaje esperado
    Serial.printf("\n<<< MENSAJE RECIBIDO de: %s (SEQ %u) >>>\n", remitente, hdr.seq_num);
    if (VERBOSE) {
        printHex("Texto cifrado (ciphertext que llego por la red)", ct, hdr.cipher_len);
        printHex("TAG recibido", tag, 16);
        printHex("Estado de la cadena (CK_rx)", p.k_rx, 32);
        printHex("Clave de ESTE mensaje para descifrar (MK)", mk, 32);
    }

    unsigned long t0 = micros();
    const char* motivo = nullptr;
    bool consumir_ratchet = false;

    if (strcmp(remitente, p.id) != 0) {
        motivo = "Remitente (ID_S) no coincide con la sesion";
    } else if (hdr.session_id != p.sid) {
        motivo = "Session ID (SID) invalido";
    } else if (hdr.seq_num <= p.rx_last) {
        motivo = "REPLAY detectado (SEQ repetido o antiguo; ademas la clave de ese mensaje ya fue descartada)";
    } else {
        mbedtls_gcm_context gcm;
        mbedtls_gcm_init(&gcm);
        mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, mk, 256);
        int ret = mbedtls_gcm_auth_decrypt(&gcm, hdr.cipher_len, hdr.nonce, 12,
                                           (const uint8_t*)&hdr, sizeof(hdr), tag, 16, ct, pt);
        mbedtls_gcm_free(&gcm);
        if (ret != 0) motivo = "Fallo de autenticacion GCM (ciphertext, cabecera o TAG alterados, o paquete forjado)";
        else consumir_ratchet = true;
    }
    unsigned long t_dec = micros() - t0;
    memset(mk, 0, sizeof(mk));

    uint8_t frame[1 + sizeof(Ack)];
    Ack ack = { hdr.seq_num, (uint8_t)(motivo ? 0 : 1) };
    frame[0] = FRAME_ACK;
    memcpy(frame + 1, &ack, sizeof(ack));
    p.sock.write(frame, sizeof(frame));

    if (!motivo) {
        p.rx_last = hdr.seq_num;
        pt[hdr.cipher_len] = '\0';
        printChunked("TEXTO DESCIFRADO (plaintext recuperado)", (const char*)pt, hdr.cipher_len);
        Serial.printf("[OK] Mensaje integro y autentico de %s. Descifrado+verificacion: %lu us\n", p.id, t_dec);
        if (consumir_ratchet) {
            avanzarCadena(p.k_rx);   // misma cadena que el emisor, solo si el mensaje fue autentico
            if (VERBOSE) {
                Serial.printf("[CADENA] Estado de recepcion avanzado para el proximo mensaje de %s.\n", p.id);
                printHex("Nuevo CK_rx", p.k_rx, 32);
            }
        }
    } else {
        Serial.printf("[RECHAZADO] Paquete de %s (SEQ %u) BLOQUEADO. Razon tecnica: %s. Tiempo: %lu us\n",
                      p.id, hdr.seq_num, motivo, t_dec);
        Serial.printf("[ALERTA] Intento de manipulacion detectado en la sesion con %s.\n", p.id);
    }
}

void recibirAck(Peer& p) {
    Ack ack;
    if (!readExact(p.sock, (uint8_t*)&ack, sizeof(ack))) { cerrarSesion(p, "ACK incompleto"); return; }
    if (!p.pendiente || ack.seq_num != p.pend_seq) return;
    unsigned long rtt = micros() - p.pend_t0;
    p.pendiente = false;
    if (ack.status == 1) {
        memcpy(p.ultimo_frame, p.pend_frame, p.pend_len);
        p.ultimo_len = p.pend_len;
    }
    Serial.printf("[ACK <- %s] SEQ %u: %s | RTT: %.2f ms\n", p.id, ack.seq_num,
                  ack.status == 1 ? "ACEPTADO" : "RECHAZADO", rtt / 1000.0);
}

void procesarPeer(Peer& p) {
    while (p.activo && p.sock.available()) {
        uint8_t tipo = 0;
        if (!readExact(p.sock, &tipo, 1)) { cerrarSesion(p, "error de lectura"); return; }
        if (tipo == FRAME_DATA) recibirData(p);
        else if (tipo == FRAME_ACK) recibirAck(p);
        else {
            Serial.printf("[ALERTA] Trama desconocida (0x%02X) de %s.\n", tipo, p.id);
            cerrarSesion(p, "trama invalida");
        }
    }
}

// =====================================================================
//  Monitor Serie
// =====================================================================
void imprimirMenu() {
    Serial.println("\n--- NODO P2P SEGURO (PROYECTO 1) ---");
    Serial.println(" [texto]       Envia el texto cifrado a todas las placas conectadas");
    Serial.println(" [@ID texto]   Envia solo a una placa (ej: @ESP32_Christopher hola)");
    Serial.println(" [1]           Mensaje de prueba normal");
    Serial.println(" [2]           Test: alterar ciphertext");
    Serial.println(" [3]           Test: alterar TAG");
    Serial.println(" [4]           Test: replay del ultimo paquete aceptado");
    Serial.println(" [5]           Test: falsificar remitente (ID_S)");
    Serial.println(" [6]           Test: inyectar paquete forjado sin la clave de sesion");
    Serial.println(" [p]           Ver estado de las placas");
    Serial.println(" [k]           Ver el estado de las cadenas de claves (CK)");
    Serial.println(" [m]           Ver este menu");
    Serial.println("------------------------------------\n");
}

void imprimirPeers() {
    Serial.printf("\nYo: %s (%s)\n", MY_ID, WiFi.localIP().toString().c_str());
    for (int i = 0; i < MAX_PEERS; i++) {
        Peer& p = peers[i];
        if (esYo(p)) continue;
        if (p.activo)
            Serial.printf(" - %-19s %-15s CONECTADO (SID 0x%08X, TX SEQ %u, RX SEQ %u)\n",
                          p.id, p.ip, p.sid, p.tx_seq, p.rx_last);
        else
            Serial.printf(" - %-19s %-15s %s\n", p.id, p.ip[0] ? p.ip : "-",
                          p.ip[0] ? "desconectado" : "no descubierta aun");
    }
    Serial.println();
}

void imprimirClaves() {
    Serial.println("\n--- Estado de las cadenas de claves (CK avanza con cada mensaje) ---");
    for (int i = 0; i < MAX_PEERS; i++) {
        Peer& p = peers[i];
        if (esYo(p) || !p.activo) continue;
        Serial.printf("Con %s:\n", p.id);
        printHex("  CK_tx (proximo envio)", p.k_tx, 32);
        printHex("  CK_rx (proxima recepcion)", p.k_rx, 32);
    }
    Serial.println();
}

void procesarLinea() {
    linea[linea_len] = '\0';
    size_t len = linea_len;
    linea_len = 0;
    if (len == 0) return;

    if (len == 1 && (linea[0] == 'p' || linea[0] == 'P')) { imprimirPeers(); return; }
    if (len == 1 && (linea[0] == 'm' || linea[0] == 'M')) { imprimirMenu(); return; }
    if (len == 1 && (linea[0] == 'k' || linea[0] == 'K')) { imprimirClaves(); return; }

    const char* texto = linea;
    int destino = -1;
    if (linea[0] == '@') {
        char* esp = strchr(linea, ' ');
        if (!esp) { Serial.println("Uso: @ID texto"); return; }
        *esp = '\0';
        destino = buscarPeer(linea + 1);
        if (destino < 0) { Serial.printf("No conozco la placa '%s'\n", linea + 1); return; }
        texto = esp + 1;
    }

    int modo = 1;
    if (strlen(texto) == 1 && texto[0] >= '1' && texto[0] <= '6') {
        modo = texto[0] - '0';
        texto = MENSAJE_PRUEBA;
    }

    int enviados = 0;
    for (int i = 0; i < MAX_PEERS; i++) {
        if (destino >= 0 && i != destino) continue;
        Peer& p = peers[i];
        if (esYo(p) || !p.activo) continue;
        if (modo == 4) probarReplay(p);
        else enviarA(p, texto, modo);
        enviados++;
    }
    if (enviados == 0) Serial.println("No hay ninguna placa conectada para enviar.");
}

// =====================================================================
//  setup / loop
// =====================================================================
void setup() {
    Serial.begin(115200);
    delay(1000);
    Serial.printf("\n=== Nodo P2P seguro: %s ===\n", MY_ID);

    if (strlen(MY_ID) == 0 || strlen(MY_ID) > 19) {
        Serial.println("[CONFIG] MY_ID debe tener entre 1 y 19 caracteres.");
        while (true) delay(1000);
    }

    // Curva P-256 y clave privada de identidad de esta placa
    mbedtls_ecp_group_init(&ECP_GRP);
    mbedtls_mpi_init(&MY_D);
    mbedtls_ecp_group_load(&ECP_GRP, MBEDTLS_ECP_DP_SECP256R1);
    uint8_t priv_bytes[32];
    if (!hexABytes(MY_PRIV_HEX, priv_bytes, 32) || mbedtls_mpi_read_binary(&MY_D, priv_bytes, 32) != 0) {
        Serial.println("\n[CONFIG] MY_PRIV_HEX no es una clave privada valida (64 caracteres hex).");
        Serial.println("         Genera TU clave en el PC (solo la tuya):");
        Serial.println("           python nodo_pc.py --genkey <TU_ID>");
        Serial.println("         y pega la privada en MY_PRIV_HEX y el bloque AUTORIZADOS (python nodo_pc.py --block).");
        while (true) delay(1000);
    }
    memset(priv_bytes, 0, sizeof(priv_bytes));

    // Lista de autorizados con su clave publica
    bool en_lista = false;
    for (int i = 0; i < MAX_PEERS; i++) {
        peers[i].id = AUTORIZADOS[i].id;
        peers[i].tiene_pub = hexABytes(AUTORIZADOS[i].pub_hex, peers[i].pub, 65) && clavePublicaValida(peers[i].pub);
        peers[i].ip[0] = '\0';
        peers[i].activo = false;
        peers[i].pendiente = false;
        peers[i].ultimo_len = 0;
        peers[i].ultimo_intento = 0;
        if (esYo(peers[i])) en_lista = true;
    }
    if (!en_lista) {
        Serial.printf("[CONFIG] '%s' no esta en AUTORIZADOS.\n", MY_ID);
        while (true) delay(1000);
    }

    // Comprobar que MI clave privada corresponde a MI clave publica de la lista:
    // firmo algo y lo verifico con la publica grabada.
    Peer* yo = &peers[buscarPeer(MY_ID)];
    uint8_t Tprueba[32], sigprueba[64];
    memset(Tprueba, 0x5A, sizeof(Tprueba));
    if (!yo->tiene_pub || !firmarTranscript("P1-INIT", Tprueba, sigprueba) ||
        !verificarFirma(yo->pub, "P1-INIT", Tprueba, sigprueba)) {
        Serial.println("\n[CONFIG] MY_PRIV_HEX no corresponde a la clave publica de este MY_ID en AUTORIZADOS.");
        Serial.println("         Revisa que pegaste la privada y la publica del MISMO dispositivo.");
        while (true) delay(1000);
    }

    // Huellas: permiten comprobar a simple vista que todas las placas tienen la misma lista
    Serial.println("Dispositivos autorizados (huella de su clave publica):");
    for (int i = 0; i < MAX_PEERS; i++) {
        char hu[9];
        if (peers[i].tiene_pub) huellaPub(peers[i].pub, hu); else strcpy(hu, "--------");
        Serial.printf("  %-19s %s%s%s\n", peers[i].id, hu, esYo(peers[i]) ? "  (yo)" : "",
                      peers[i].tiene_pub ? "" : "  [SIN CLAVE PUBLICA VALIDA: sera rechazado]");
    }

    mbedtls_mpi_init(&DH_P);
    mbedtls_mpi_init(&DH_G_mpi);
    mbedtls_mpi_read_string(&DH_P, 16, DH_P_HEX);
    mbedtls_mpi_lset(&DH_G_mpi, DH_G);
    imprimirParametrosDH();

    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    Serial.printf("Conectando a %s", WIFI_SSID);
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    WiFi.setSleep(false);
    Serial.printf("\nWi-Fi conectado. IP: %s\n", WiFi.localIP().toString().c_str());

    servidor.begin();
    udp.begin(PUERTO_DESC);
    Serial.printf("Escuchando en TCP %u, anuncios en UDP %u\n", PUERTO, PUERTO_DESC);
    imprimirMenu();
}

void loop() {
    if (millis() - ultimo_anuncio > ANUNCIO_MS) {
        anunciarme();
        ultimo_anuncio = millis();
    }
    escucharAnuncios();

    WiFiClient entrante = servidor.accept();
    if (entrante) atenderEntrante(entrante);

    for (int i = 0; i < MAX_PEERS; i++) {
        Peer& p = peers[i];
        if (esYo(p) || p.activo || p.ip[0] == '\0') continue;
        if (strcmp(MY_ID, p.id) < 0 && millis() - p.ultimo_intento > REINTENTO_MS) conectarA(p);
    }

    for (int i = 0; i < MAX_PEERS; i++) {
        Peer& p = peers[i];
        if (!p.activo) continue;
        if (!p.sock.connected() && !p.sock.available()) { cerrarSesion(p, "la placa se desconecto"); continue; }
        procesarPeer(p);
    }

    while (Serial.available()) {
        char c = Serial.read();
        ultimo_char = millis();
        if (c == '\n' || c == '\r') procesarLinea();
        else if (linea_len < sizeof(linea) - 1) linea[linea_len++] = c;
    }
    if (linea_len > 0 && millis() - ultimo_char > 100) procesarLinea();
}
