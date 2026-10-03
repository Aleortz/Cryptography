// =====================================================================
//  Proyecto 1 - Secure Wireless Messaging for IoT Devices
//  Nodo peer-to-peer (ESP32). Sin servidor: cada placa escucha en
//  PUERTO y se conecta directamente con las demás placas autorizadas.
//
//  Handshake (por cada par de placas):
//    - ECDHE P-256 (claves efímeras nuevas en cada sesión -> forward secrecy)
//    - Autenticación mutua con ECDSA P-256 sobre el transcript completo
//      (IDs, nonces y claves efímeras). Cada placa tiene grabadas las claves
//      públicas de las placas autorizadas: no se confía en nada recibido.
//    - HKDF-SHA256 -> una clave AES-256 por dirección + Session ID
//  Mensajes:
//    - AES-256-GCM, cabecera completa como AAD
//    - SEQ estrictamente creciente por peer y por dirección (anti-replay)
//  Toda la criptografía es de mbedTLS (incluido en el core ESP32 de Arduino).
//
//  Requiere el archivo secrets.h de esta placa (lo genera tools/keygen.py).
// =====================================================================
#include <WiFi.h>
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/md.h"
#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#if __has_include(<esp_random.h>)
  #include <esp_random.h>
#endif

#ifdef SET_LOOP_TASK_STACK_SIZE
SET_LOOP_TASK_STACK_SIZE(16 * 1024);   // margen para las operaciones de curva elíptica
#endif

// --- Lista de dispositivos autorizados (la llena secrets.h) ---
struct Dispositivo {
    const char* id;        // máx. 19 caracteres
    const char* ip;        // IP de la placa en la red WiFi
    uint8_t pub[65];       // clave pública ECDSA P-256 (formato sin comprimir: 04 || X || Y)
};
#include "secrets.h"       // WIFI_SSID, WIFI_PASS, MY_ID, MY_PRIVATE_KEY, DISPOSITIVOS[]

// --- Parámetros del protocolo ---
const uint16_t PUERTO = 8080;
const uint16_t MAX_CIPHER_LEN = 512;
const unsigned long TIMEOUT_MS = 5000;
const unsigned long REINTENTO_MS = 3000;
const uint8_t FRAME_DATA = 0x01;   // [0x01][PacketHeader][C][TAG]
const uint8_t FRAME_ACK  = 0x02;   // [0x02][Ack]
const char MAGIC[4] = { 'P', '1', 'v', '1' };
const char* MENSAJE_PRUEBA = "Temp: 24.5C | Hum: 60% | Nodo Activo";
const int MAX_PEERS = sizeof(DISPOSITIVOS) / sizeof(DISPOSITIVOS[0]);

// --- Mensajes del handshake ---
struct __attribute__((packed)) Hello {        // HS1: iniciador -> respondedor
    char magic[4];
    char id[20];
    uint8_t nonce[16];
    uint8_t epub[65];                         // clave pública efímera ECDH
};
struct __attribute__((packed)) HelloReply {   // HS2: respondedor -> iniciador
    uint8_t status;                           // 1 = continuar, 0 = no autorizado
    char id[20];
    uint8_t nonce[16];
    uint8_t epub[65];
    uint8_t sig[64];                          // ECDSA(r||s) sobre "P1-RESP" || T
};
struct __attribute__((packed)) Finish {       // HS3: iniciador -> respondedor
    uint8_t sig[64];                          // ECDSA(r||s) sobre "P1-INIT" || T
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
struct __attribute__((packed)) Ack {          // confirmación de recepción (solo para métricas)
    uint32_t seq_num;
    uint8_t status;                           // 1 = aceptado, 0 = rechazado
};

const size_t MAX_FRAME = 1 + sizeof(PacketHeader) + MAX_CIPHER_LEN + 16;

// --- Estado de cada peer ---
struct Peer {
    const Dispositivo* cfg;
    WiFiClient sock;
    bool activo;
    uint8_t k_tx[32];              // clave para lo que YO envío a este peer
    uint8_t k_rx[32];              // clave para lo que este peer me envía
    uint32_t sid;
    uint32_t tx_seq;
    uint32_t rx_last;              // último SEQ aceptado (anti-replay)
    unsigned long ultimo_intento;
    // Métricas (RTT) y prueba de replay
    bool pendiente;
    uint32_t pend_seq;
    unsigned long pend_t0;
    uint8_t pend_frame[MAX_FRAME];
    size_t pend_len;
    uint8_t ultimo_frame[MAX_FRAME];   // copia exacta del último paquete que el peer ACEPTÓ
    size_t ultimo_len;
};

Peer peers[MAX_PEERS];
WiFiServer servidor(PUERTO);
mbedtls_ecp_group grp;
mbedtls_mpi my_d;
const Dispositivo* yo = nullptr;

char linea[201];
size_t linea_len = 0;
unsigned long ultimo_char = 0;

// =====================================================================
//  Primitivas criptográficas (todas de mbedTLS)
// =====================================================================
static int rng(void*, unsigned char* out, size_t len) {
    esp_fill_random(out, len);     // TRNG por hardware del ESP32
    return 0;
}

void sha256(const uint8_t* in, size_t len, uint8_t out[32]) {
    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), in, len, out);
}

// HKDF-SHA256 (RFC 5869)
bool hkdf(const uint8_t* salt, size_t salt_len, const uint8_t* ikm, size_t ikm_len,
          const uint8_t* info, size_t info_len, uint8_t* okm, size_t okm_len) {
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
#if defined(MBEDTLS_HKDF_C) && !defined(FORZAR_HKDF_MANUAL)
    return mbedtls_hkdf(md, salt, salt_len, ikm, ikm_len, info, info_len, okm, okm_len) == 0;
#else
    // Si el core no trae MBEDTLS_HKDF_C, misma construcción con HMAC-SHA256 de mbedTLS
    uint8_t prk[32], t[32];
    if (mbedtls_md_hmac(md, salt, salt_len, ikm, ikm_len, prk) != 0) return false;   // Extract
    size_t hecho = 0;
    uint8_t contador = 1, t_len = 0;
    while (hecho < okm_len) {                                                            // Expand
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

bool puntoValido(const uint8_t pub[65]) {
    mbedtls_ecp_point Q;
    mbedtls_ecp_point_init(&Q);
    bool ok = mbedtls_ecp_point_read_binary(&grp, &Q, pub, 65) == 0 &&
              mbedtls_ecp_check_pubkey(&grp, &Q) == 0;
    mbedtls_ecp_point_free(&Q);
    return ok;
}

bool generarEfimera(mbedtls_mpi* d, uint8_t pub[65]) {
    mbedtls_ecp_point Q;
    mbedtls_ecp_point_init(&Q);
    size_t olen = 0;
    bool ok = mbedtls_ecdh_gen_public(&grp, d, &Q, rng, NULL) == 0 &&
              mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, pub, 65) == 0 &&
              olen == 65;
    mbedtls_ecp_point_free(&Q);
    return ok;
}

bool secretoECDH(const mbedtls_mpi* d, const uint8_t peer_pub[65], uint8_t z[32]) {
    mbedtls_ecp_point Q;
    mbedtls_mpi zz;
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&zz);
    bool ok = mbedtls_ecp_point_read_binary(&grp, &Q, peer_pub, 65) == 0 &&
              mbedtls_ecp_check_pubkey(&grp, &Q) == 0 &&
              mbedtls_ecdh_compute_shared(&grp, &zz, &Q, d, rng, NULL) == 0 &&
              mbedtls_mpi_write_binary(&zz, z, 32) == 0;
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&zz);
    return ok;
}

// Firma ECDSA de SHA256(etiqueta || T) con la clave privada de esta placa
bool firmar(const char* etiqueta, const uint8_t T[32], uint8_t sig[64]) {
    uint8_t buf[7 + 32], h[32];
    memcpy(buf, etiqueta, 7);
    memcpy(buf + 7, T, 32);
    sha256(buf, sizeof(buf), h);
    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    bool ok = mbedtls_ecdsa_sign(&grp, &r, &s, &my_d, h, 32, rng, NULL) == 0 &&
              mbedtls_mpi_write_binary(&r, sig, 32) == 0 &&
              mbedtls_mpi_write_binary(&s, sig + 32, 32) == 0;
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    return ok;
}

// Verifica con la clave pública GRABADA del peer (nunca con una recibida por la red)
bool verificarFirma(const uint8_t pub[65], const char* etiqueta, const uint8_t T[32], const uint8_t sig[64]) {
    uint8_t buf[7 + 32], h[32];
    memcpy(buf, etiqueta, 7);
    memcpy(buf + 7, T, 32);
    sha256(buf, sizeof(buf), h);
    mbedtls_ecp_point Q;
    mbedtls_mpi r, s;
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    bool ok = mbedtls_ecp_point_read_binary(&grp, &Q, pub, 65) == 0 &&
              mbedtls_mpi_read_binary(&r, sig, 32) == 0 &&
              mbedtls_mpi_read_binary(&s, sig + 32, 32) == 0 &&
              mbedtls_ecdsa_verify(&grp, h, 32, &Q, &r, &s) == 0;
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    return ok;
}

// T = SHA256(Hello || id_R || nonce_R || epub_R): cubre ambos IDs, nonces y claves efímeras
void transcript(const Hello& h, const HelloReply& r, uint8_t T[32]) {
    uint8_t buf[sizeof(Hello) + 20 + 16 + 65];
    size_t n = 0;
    memcpy(buf + n, &h, sizeof(Hello)); n += sizeof(Hello);
    memcpy(buf + n, r.id, 20);          n += 20;
    memcpy(buf + n, r.nonce, 16);       n += 16;
    memcpy(buf + n, r.epub, 65);        n += 65;
    sha256(buf, n, T);
}

// okm = k_iniciador->respondedor (32) || k_respondedor->iniciador (32) || SID (4)
bool derivarClaves(const uint8_t z[32], const Hello& h, const HelloReply& r, const uint8_t T[32], uint8_t okm[68]) {
    uint8_t salt[32], info[7 + 32];
    memcpy(salt, h.nonce, 16);
    memcpy(salt + 16, r.nonce, 16);
    memcpy(info, "P1-KEYS", 7);
    memcpy(info + 7, T, 32);
    return hkdf(salt, 32, z, 32, info, sizeof(info), okm, 68);
}

// =====================================================================
//  Utilidades de red
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
        if (strcmp(peers[i].cfg->id, id) == 0) return i;
    return -1;
}

void cerrarSesion(Peer& p, const char* motivo) {
    if (p.activo) Serial.printf("[-] Sesion con %s cerrada: %s\n", p.cfg->id, motivo);
    p.sock.stop();
    p.activo = false;
    p.pendiente = false;
}

void establecerSesion(Peer& p, WiFiClient& c, const uint8_t okm[68], bool soy_iniciador, unsigned long t_hs) {
    if (p.activo) p.sock.stop();   // la placa se reconectó: reemplaza la sesión anterior
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
    Serial.printf("[OK] Sesion segura con %s (%s) | SID: 0x%08X | Handshake: %lu ms\n",
                  p.cfg->id, soy_iniciador ? "yo inicie" : "el inicio", p.sid, t_hs);
}

// =====================================================================
//  Handshake
// =====================================================================

// Esta placa inicia la conexión hacia p (regla: inicia la de ID menor)
void conectarA(Peer& p) {
    p.ultimo_intento = millis();
    WiFiClient c;
    if (!c.connect(p.cfg->ip, PUERTO, 1000)) return;   // el peer aún no está encendido
    c.setNoDelay(true);
    unsigned long t0 = millis();

    Hello h;
    memset(&h, 0, sizeof(h));
    memcpy(h.magic, MAGIC, 4);
    strncpy(h.id, MY_ID, sizeof(h.id) - 1);
    rng(NULL, h.nonce, sizeof(h.nonce));
    mbedtls_mpi e;
    mbedtls_mpi_init(&e);
    const char* error = nullptr;
    HelloReply r;
    Finish f;
    uint8_t T[32], z[32], okm[68], resultado = 0;

    if (!generarEfimera(&e, h.epub)) error = "no se pudo generar la clave efimera";
    else if (c.write((const uint8_t*)&h, sizeof(h)) != sizeof(h)) error = "fallo al enviar Hello";
    else if (!readExact(c, (uint8_t*)&r, sizeof(r))) error = "no respondio al handshake";
    else if (r.status != 1) error = "me rechazo (no estoy en su lista de autorizados)";
    else if (strncmp(r.id, p.cfg->id, sizeof(r.id)) != 0) error = "respondio con otra identidad";
    else if (!puntoValido(r.epub)) error = "clave efimera invalida";
    else {
        transcript(h, r, T);
        if (!verificarFirma(p.cfg->pub, "P1-RESP", T, r.sig)) {
            Serial.printf("[ALERTA] Firma de %s INVALIDA: posible suplantacion o MITM. Abortando.\n", p.cfg->id);
            error = "firma invalida";
        } else if (!firmar("P1-INIT", T, f.sig)) error = "no se pudo firmar";
        else if (c.write((const uint8_t*)&f, sizeof(f)) != sizeof(f)) error = "fallo al enviar Finish";
        else if (!readExact(c, &resultado, 1) || resultado != 1) error = "rechazo mi firma";
        else if (!secretoECDH(&e, r.epub, z) || !derivarClaves(z, h, r, T, okm)) error = "fallo al derivar claves";
    }
    mbedtls_mpi_free(&e);

    if (error) {
        Serial.printf("[X] Handshake con %s fallido: %s\n", p.cfg->id, error);
        c.stop();
        return;
    }
    establecerSesion(p, c, okm, true, millis() - t0);
    memset(z, 0, sizeof(z));
    memset(okm, 0, sizeof(okm));
}

// Otra placa (o un intruso) se conectó a nuestro puerto
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
    if (idx < 0 || peers[idx].cfg == yo) {
        Serial.printf("[ALERTA] Dispositivo NO AUTORIZADO '%s' desde %s. Rechazado.\n", id, ip.c_str());
        c.write((const uint8_t*)&r, sizeof(r));   // status = 0
        c.stop();
        return;
    }
    Peer& p = peers[idx];
    if (!puntoValido(h.epub)) {
        Serial.printf("[ALERTA] Clave efimera invalida de '%s'. Rechazado.\n", id);
        c.stop();
        return;
    }

    r.status = 1;
    strncpy(r.id, MY_ID, sizeof(r.id) - 1);
    rng(NULL, r.nonce, sizeof(r.nonce));
    mbedtls_mpi e;
    mbedtls_mpi_init(&e);
    uint8_t T[32], z[32], okm[68], resultado = 0;
    Finish f;
    const char* error = nullptr;

    if (!generarEfimera(&e, r.epub)) error = "no se pudo generar la clave efimera";
    else {
        transcript(h, r, T);
        if (!firmar("P1-RESP", T, r.sig)) error = "no se pudo firmar";
        else if (c.write((const uint8_t*)&r, sizeof(r)) != sizeof(r)) error = "fallo al enviar HelloReply";
        else if (!readExact(c, (uint8_t*)&f, sizeof(f))) error = "no envio su firma";
        else if (!verificarFirma(p.cfg->pub, "P1-INIT", T, f.sig)) {
            Serial.printf("[ALERTA] '%s' desde %s presento una firma INVALIDA (suplantacion). Rechazado.\n", id, ip.c_str());
            error = "firma invalida";
        }
        else if (!secretoECDH(&e, h.epub, z) || !derivarClaves(z, h, r, T, okm)) error = "fallo al derivar claves";
    }
    mbedtls_mpi_free(&e);

    resultado = (error == nullptr) ? 1 : 0;
    c.write(&resultado, 1);
    if (error) {
        Serial.printf("[X] Handshake entrante de '%s' fallido: %s\n", id, error);
        c.stop();
        return;
    }
    establecerSesion(p, c, okm, false, millis() - t0);
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
    rng(NULL, hdr.nonce, 8);                    // N = 8 bytes aleatorios || SEQ
    memcpy(hdr.nonce + 8, &hdr.seq_num, 4);
    hdr.cipher_len = len;

    uint8_t* ct = frame + 1 + sizeof(PacketHeader);
    uint8_t* tag = ct + len;

    unsigned long t0 = micros();
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, p.k_tx, 256);
    mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, len, hdr.nonce, 12,
                              (const uint8_t*)&hdr, sizeof(hdr), (const uint8_t*)texto, ct, 16, tag);
    mbedtls_gcm_free(&gcm);
    unsigned long t_enc = micros() - t0;

    // Pruebas de seguridad (Sección 4): se altera el paquete DESPUÉS de cifrar
    if (modo == 2) { ct[0] ^= 0xFF;  Serial.printf("[TEST -> %s] Alterando 1 byte del ciphertext\n", p.cfg->id); }
    if (modo == 3) { tag[0] ^= 0xFF; Serial.printf("[TEST -> %s] Alterando 1 byte del TAG\n", p.cfg->id); }
    if (modo == 5) {
        memset(hdr.sender_id, 0, sizeof(hdr.sender_id));
        strncpy(hdr.sender_id, "ESP32_Intruso", sizeof(hdr.sender_id) - 1);
        Serial.printf("[TEST -> %s] Falsificando el remitente (ID_S) en la cabecera\n", p.cfg->id);
    }
    memcpy(frame + 1, &hdr, sizeof(hdr));
    size_t total = 1 + sizeof(PacketHeader) + len + 16;

    memcpy(p.pend_frame, frame, total);
    p.pend_len = total;
    p.pend_seq = hdr.seq_num;
    p.pendiente = true;
    p.pend_t0 = micros();
    p.sock.write(frame, total);

    Serial.printf("[ENVIADO -> %s] SEQ %u | Plaintext: %u B | Paquete: %u B (+%u B) | Cifrado: %lu us\n",
                  p.cfg->id, hdr.seq_num, (unsigned)len, (unsigned)(total - 1),
                  (unsigned)(total - 1 - len), t_enc);
}

// Prueba de replay: retransmite byte por byte el último paquete que el peer ACEPTÓ
void probarReplay(Peer& p) {
    if (p.ultimo_len == 0) {
        Serial.printf("[TEST -> %s] Primero envia un mensaje normal para tener un paquete aceptado.\n", p.cfg->id);
        return;
    }
    PacketHeader hdr;
    memcpy(&hdr, p.ultimo_frame + 1, sizeof(hdr));
    Serial.printf("[TEST -> %s] Retransmitiendo paquete ya aceptado (SEQ %u), identico byte por byte\n",
                  p.cfg->id, hdr.seq_num);
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
        Serial.printf("[ALERTA] %s envio una longitud invalida (%u B).\n", p.cfg->id, hdr.cipher_len);
        cerrarSesion(p, "longitud invalida");
        return;
    }
    if (!readExact(p.sock, ct, hdr.cipher_len) || !readExact(p.sock, tag, 16)) {
        cerrarSesion(p, "paquete incompleto");
        return;
    }

    unsigned long t0 = micros();
    const char* motivo = nullptr;
    char remitente[21] = {0};
    memcpy(remitente, hdr.sender_id, 20);

    if (strcmp(remitente, p.cfg->id) != 0) {
        motivo = "Remitente (ID_S) no coincide con la sesion";
    } else if (hdr.session_id != p.sid) {
        motivo = "Session ID (SID) invalido";
    } else if (hdr.seq_num <= p.rx_last) {
        motivo = "REPLAY detectado (SEQ repetido o antiguo)";
    } else {
        mbedtls_gcm_context gcm;
        mbedtls_gcm_init(&gcm);
        mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, p.k_rx, 256);
        int ret = mbedtls_gcm_auth_decrypt(&gcm, hdr.cipher_len, hdr.nonce, 12,
                                           (const uint8_t*)&hdr, sizeof(hdr), tag, 16, ct, pt);
        mbedtls_gcm_free(&gcm);
        if (ret != 0) motivo = "Fallo de autenticacion GCM (ciphertext, cabecera o TAG alterados)";
    }
    unsigned long t_dec = micros() - t0;

    uint8_t frame[1 + sizeof(Ack)];
    Ack ack = { hdr.seq_num, (uint8_t)(motivo ? 0 : 1) };
    frame[0] = FRAME_ACK;
    memcpy(frame + 1, &ack, sizeof(ack));
    p.sock.write(frame, sizeof(frame));

    if (!motivo) {
        p.rx_last = hdr.seq_num;
        pt[hdr.cipher_len] = '\0';
        Serial.printf("[RECIBIDO <- %s] SEQ %u | Descifrado+verificacion: %lu us\n    \"%s\"\n",
                      p.cfg->id, hdr.seq_num, t_dec, (const char*)pt);
    } else {
        Serial.printf("[RECHAZADO <- %s] SEQ %u | %lu us | Motivo: %s\n", p.cfg->id, hdr.seq_num, t_dec, motivo);
    }
}

void recibirAck(Peer& p) {
    Ack ack;
    if (!readExact(p.sock, (uint8_t*)&ack, sizeof(ack))) { cerrarSesion(p, "ACK incompleto"); return; }
    if (!p.pendiente || ack.seq_num != p.pend_seq) return;
    unsigned long rtt = micros() - p.pend_t0;
    p.pendiente = false;
    if (ack.status == 1) {   // guardamos el paquete aceptado para la prueba de replay
        memcpy(p.ultimo_frame, p.pend_frame, p.pend_len);
        p.ultimo_len = p.pend_len;
    }
    Serial.printf("[ACK <- %s] SEQ %u: %s | RTT: %.2f ms\n", p.cfg->id, ack.seq_num,
                  ack.status == 1 ? "ACEPTADO" : "RECHAZADO", rtt / 1000.0);
}

void procesarPeer(Peer& p) {
    while (p.activo && p.sock.available()) {
        uint8_t tipo = 0;
        if (!readExact(p.sock, &tipo, 1)) { cerrarSesion(p, "error de lectura"); return; }
        if (tipo == FRAME_DATA) recibirData(p);
        else if (tipo == FRAME_ACK) recibirAck(p);
        else {
            Serial.printf("[ALERTA] Trama desconocida (0x%02X) de %s.\n", tipo, p.cfg->id);
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
    Serial.println(" [@ID texto]   Envia solo a una placa (ej: @ESP32_Bryan hola)");
    Serial.println(" [1]           Mensaje de prueba normal");
    Serial.println(" [2]           Test: alterar ciphertext");
    Serial.println(" [3]           Test: alterar TAG");
    Serial.println(" [4]           Test: replay del ultimo paquete aceptado");
    Serial.println(" [5]           Test: falsificar remitente (ID_S)");
    Serial.println(" [p]           Ver estado de las placas");
    Serial.println(" [m]           Ver este menu");
    Serial.println("------------------------------------\n");
}

void imprimirPeers() {
    Serial.printf("\nYo: %s (%s)\n", MY_ID, WiFi.localIP().toString().c_str());
    for (int i = 0; i < MAX_PEERS; i++) {
        Peer& p = peers[i];
        if (p.cfg == yo) continue;
        if (p.activo)
            Serial.printf(" - %-19s %-15s CONECTADO (SID 0x%08X, TX SEQ %u, RX SEQ %u)\n",
                          p.cfg->id, p.cfg->ip, p.sid, p.tx_seq, p.rx_last);
        else
            Serial.printf(" - %-19s %-15s desconectado\n", p.cfg->id, p.cfg->ip);
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

    // Destino: una placa (@ID texto) o todas
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
    if (strlen(texto) == 1 && texto[0] >= '1' && texto[0] <= '5') {
        modo = texto[0] - '0';
        texto = MENSAJE_PRUEBA;
    }

    int enviados = 0;
    for (int i = 0; i < MAX_PEERS; i++) {
        if (destino >= 0 && i != destino) continue;
        Peer& p = peers[i];
        if (p.cfg == yo || !p.activo) continue;
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

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&my_d);
    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    mbedtls_mpi_read_binary(&my_d, MY_PRIVATE_KEY, sizeof(MY_PRIVATE_KEY));

    for (int i = 0; i < MAX_PEERS; i++) {
        peers[i].cfg = &DISPOSITIVOS[i];
        peers[i].activo = false;
        peers[i].pendiente = false;
        peers[i].ultimo_len = 0;
        peers[i].ultimo_intento = 0;
        if (strcmp(DISPOSITIVOS[i].id, MY_ID) == 0) yo = &DISPOSITIVOS[i];
    }

    // Verificar que la clave privada corresponde a nuestra clave pública de la lista
    bool clave_ok = false;
    if (yo) {
        mbedtls_ecp_point Q;
        mbedtls_ecp_point_init(&Q);
        uint8_t pub[65];
        size_t olen = 0;
        clave_ok = mbedtls_ecp_mul(&grp, &Q, &my_d, &grp.G, rng, NULL) == 0 &&
                   mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, pub, 65) == 0 &&
                   olen == 65 && memcmp(pub, yo->pub, 65) == 0;
        mbedtls_ecp_point_free(&Q);
    }
    if (!clave_ok) {
        Serial.println("[ERROR] secrets.h no corresponde a esta placa (MY_ID o la clave privada no coinciden).");
        Serial.println("        Vuelve a generarlo con tools/keygen.py. Deteniendo.");
        while (true) delay(1000);
    }

    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    WiFi.setSleep(false);   // sin ahorro de energía: baja la latencia de cientos de ms a pocos ms
    String mi_ip = WiFi.localIP().toString();
    Serial.printf("\nWi-Fi conectado. IP: %s\n", mi_ip.c_str());
    if (strcmp(mi_ip.c_str(), yo->ip) != 0)
        Serial.printf("[AVISO] secrets.h dice que mi IP es %s. Actualizala en keygen.py y regenera los secrets de TODAS las placas.\n", yo->ip);

    servidor.begin();
    Serial.printf("Escuchando en el puerto %u\n", PUERTO);
    imprimirMenu();
}

void loop() {
    // 1. Conexiones entrantes (otras placas o intrusos)
    WiFiClient entrante = servidor.accept();
    if (entrante) atenderEntrante(entrante);

    // 2. Conexiones salientes: inicia la placa con el ID menor (evita conexiones duplicadas)
    for (int i = 0; i < MAX_PEERS; i++) {
        Peer& p = peers[i];
        if (p.cfg == yo || p.activo) continue;
        if (strcmp(MY_ID, p.cfg->id) < 0 && millis() - p.ultimo_intento > REINTENTO_MS) conectarA(p);
    }

    // 3. Mensajes de las placas conectadas
    for (int i = 0; i < MAX_PEERS; i++) {
        Peer& p = peers[i];
        if (!p.activo) continue;
        if (!p.sock.connected() && !p.sock.available()) { cerrarSesion(p, "la placa se desconecto"); continue; }
        procesarPeer(p);
    }

    // 4. Monitor Serie (funciona con cualquier ajuste de fin de línea)
    while (Serial.available()) {
        char c = Serial.read();
        ultimo_char = millis();
        if (c == '\n' || c == '\r') procesarLinea();
        else if (linea_len < sizeof(linea) - 1) linea[linea_len++] = c;
    }
    if (linea_len > 0 && millis() - ultimo_char > 100) procesarLinea();
}
