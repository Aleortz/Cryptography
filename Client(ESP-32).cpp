#include <WiFi.h>
#include <cstdint>
#include "mbedtls/gcm.h"
#include "mbedtls/sha256.h"

// --- Configuración de Red e Identidad ---
const char* ssid = "PLUS_RESIDENCIAS CHANCOSA";
const char* password = "elcreador90"; 
const char* host_servidor = "192.168.0.105"; // IP de tu laptop
const uint16_t puerto = 8080;
const char* CLIENT_ID = "ESP32_Christopher"; // Cambiar a "ESP32_Demian" en la 2da placa

WiFiClient client;

// --- Parámetros Públicos Diffie-Hellman ---
const uint64_t DH_P = 2147483647; 
const uint64_t DH_G = 16807;

// --- Estructuras de Protocolo ---
struct __attribute__((packed)) ServerHandshake {
    uint8_t auth_status;       // 1 = Autorizado, 0 = Rechazado
    uint32_t session_id;       // SID asignado por el servidor
    uint64_t server_dh_public;
    uint64_t rsa_signature;
    uint64_t rsa_e; 
    uint64_t rsa_n; 
};

// Formato: ID_S || SID || SEQ || N (Se autentica como AAD en GCM)
struct __attribute__((packed)) PacketHeader {
    char sender_id[20];        // ID_S: Identificador del remitente
    uint32_t session_id;       // SID: Identificador de la sesión
    uint32_t seq_num;          // SEQ: Número de secuencia contra Replay
    uint8_t nonce[12];         // N: Nonce de 96 bits para AES-GCM
    uint16_t cipher_len;       // Longitud de C
};

// --- Variables de Estado Criptográfico ---
uint8_t aes_key[32];
uint32_t current_sid = 0;
uint32_t sequence_counter = 1;

// --- Funciones Matemáticas Core (Handshake) ---
uint64_t modMult(uint64_t a, uint64_t b, uint64_t mod) {
    uint64_t res = 0;
    a = a % mod;
    while (b > 0) {
        if (b & 1) res = (res + a) % mod;
        a = (a << 1) % mod; 
        b >>= 1;
    }
    return res;
}

uint64_t modExp(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t res = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp & 1) res = modMult(res, base, mod);
        exp = exp >> 1;
        base = modMult(base, base, mod);
    }
    return res;
}

bool rsaVerify(uint64_t data, uint64_t signature, uint64_t e, uint64_t n) {
    return (modExp(signature, e, n) == data);
}

bool readExact(WiFiClient& cli, uint8_t* buf, size_t len) {
    size_t read_bytes = 0;
    unsigned long start = millis();
    while (read_bytes < len && cli.connected() && (millis() - start < 5000)) {
        if (cli.available()) buf[read_bytes++] = cli.read();
    }
    return (read_bytes == len);
}

// --- Función de Envío y Pruebas de Seguridad (Sección 3, 4 y 5) ---
void enviarMensaje(const char* texto, int modo_ataque) {
    if (!client.connected()) return;

    size_t msg_len = strlen(texto);
    PacketHeader hdr;
    memset(&hdr, 0, sizeof(hdr));
    strncpy(hdr.sender_id, CLIENT_ID, sizeof(hdr.sender_id) - 1);
    hdr.session_id = current_sid;

    // Si es prueba de Replay Attack (Modo 4), repetimos el número de secuencia anterior
    if (modo_ataque == 4 && sequence_counter > 1) {
        hdr.seq_num = sequence_counter - 1;
    } else {
        hdr.seq_num = sequence_counter++;
    }

    // Construir Nonce: 8 bytes aleatorios por hardware (TRNG) + 4 bytes de SEQ
    uint32_t rand1 = esp_random();
    uint32_t rand2 = esp_random();
    memcpy(hdr.nonce, &rand1, 4);
    memcpy(hdr.nonce + 4, &rand2, 4);
    memcpy(hdr.nonce + 8, &hdr.seq_num, 4);
    hdr.cipher_len = msg_len;

    unsigned char ciphertext[msg_len];
    unsigned char tag[16];

    // --- Medición Experimental: Tiempo de Cifrado ---
    unsigned long t_start_enc = micros();

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, aes_key, 256);

    // Pasamos el PacketHeader como AAD (Additional Authenticated Data)
    // Esto protege ID_S, SID, SEQ y N contra alteraciones en tránsito
    mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, msg_len,
                              hdr.nonce, sizeof(hdr.nonce),
                              (const unsigned char*)&hdr, sizeof(PacketHeader),
                              (const unsigned char*)texto, ciphertext,
                              sizeof(tag), tag);
    mbedtls_gcm_free(&gcm);

    unsigned long t_enc = micros() - t_start_enc;

    // --- Inyección de Fallos para Pruebas de Seguridad (Sección 4) ---
    if (modo_ataque == 2) {
        Serial.println("\n[TEST] Alterando deliberadamente 1 byte del Ciphertext...");
        ciphertext[0] ^= 0xFF; 
    } else if (modo_ataque == 3) {
        Serial.println("\n[TEST] Alterando deliberadamente 1 byte del TAG de autenticacion...");
        tag[0] ^= 0xFF;
    } else if (modo_ataque == 4) {
        Serial.printf("\n[TEST] Inyectando paquete repetido (Replay Attack con SEQ=%u)...\n", hdr.seq_num);
    } else if (modo_ataque == 5) {
        Serial.println("\n[TEST] Falsificando identidad del remitente en cabecera (Header Tampering)...");
        strncpy(hdr.sender_id, "ESP32_Intruso", sizeof(hdr.sender_id) - 1);
    }

    // --- Transmisión y Medición de Latencia ---
    unsigned long t_start_net = micros();

    // Enviar Paquete: [Header (ID_S || SID || SEQ || N || Len)] + [Ciphertext (C)] + [TAG]
    client.write((const uint8_t*)&hdr, sizeof(PacketHeader));
    client.write(ciphertext, msg_len);
    client.write(tag, sizeof(tag));

    // Esperar confirmación de 1 byte del servidor para calcular RTT (Latencia)
    uint8_t ack = 0;
    readExact(client, &ack, 1);
    unsigned long t_latency = micros() - t_start_net;

    size_t total_packet_size = sizeof(PacketHeader) + msg_len + sizeof(tag);

    // --- Impresión de Métricas para el Reporte (Sección 5) ---
    Serial.println("==========================================");
    Serial.printf("Mensaje enviado (SEQ: %u | SID: 0x%08X)\n", hdr.seq_num, hdr.session_id);
    Serial.printf(" -> Tamano Plaintext: %u bytes\n", msg_len);
    Serial.printf(" -> Tamano Paquete Protegido: %u bytes (Overhead: +%u bytes)\n", 
                  total_packet_size, total_packet_size - msg_len);
    Serial.printf(" -> Tiempo de Cifrado (AES-GCM): %lu us\n", t_enc);
    Serial.printf(" -> Latencia de Comunicacion (RTT): %lu us (%.2f ms)\n", t_latency, t_latency / 1000.0);
    Serial.printf(" -> Estado del Receptor: %s\n", (ack == 1) ? "ACEPTADO (Integro)" : "RECHAZADO (Alerta MitM/Fallo)");
    Serial.println("==========================================\n");
}

void imprimirMenu() {
    Serial.println("\n--- MENU DE PRUEBAS DE SEGURIDAD (PROYECTO 1) ---");
    Serial.println("Escribe un numero en el Monitor Serie y presiona Enter:");
    Serial.println(" [1] Enviar mensaje seguro normal");
    Serial.println(" [2] Test Integridad: Modificar Ciphertext (C)");
    Serial.println(" [3] Test Autenticacion: Modificar TAG");
    Serial.println(" [4] Test Replay Protection: Reenviar SEQ anterior");
    Serial.println(" [5] Test Falsificacion: Alterar Sender ID (ID_S) en transito");
    Serial.println("-------------------------------------------------\n");
}

void setup() {
    Serial.begin(115200);
    delay(1000);

    Serial.printf("\nIniciando nodo IoT: %s\n", CLIENT_ID);
    WiFi.begin(ssid, password);
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    Serial.println("\nWi-Fi Conectado. IP: " + WiFi.localIP().toString());

    client.setNoDelay(true);
    if (client.connect(host_servidor, puerto)) {
        // 1. Enviar identidad para autenticación de dispositivo
        char id_buf[20] = {0};
        strncpy(id_buf, CLIENT_ID, 19);
        client.write((const uint8_t*)id_buf, 20);

        // 2. Recibir Handshake del Servidor
        ServerHandshake payload;
        if (readExact(client, (uint8_t*)&payload, sizeof(ServerHandshake))) {
            if (payload.auth_status == 0) {
                Serial.println("[ERROR] Dispositivo no autorizado por el servidor. Conexion rechazada.");
                client.stop();
                return;
            }

            if (!rsaVerify(payload.server_dh_public, payload.rsa_signature, payload.rsa_e, payload.rsa_n)) {
                Serial.println("[ALERTA MITM] Firma RSA del servidor invalida. Abortando.");
                client.stop();
                return;
            }

            current_sid = payload.session_id;
            Serial.printf("[OK] Servidor autenticado. Session ID (SID): 0x%08X\n", current_sid);

            // 3. Generar par Diffie-Hellman usando el TRNG físico del ESP32
            uint64_t client_dh_private = (esp_random() % (DH_P - 2)) + 1;
            uint64_t client_dh_public = modExp(DH_G, client_dh_private, DH_P);
            client.write((const uint8_t*)&client_dh_public, sizeof(uint64_t));

            uint64_t shared_secret = modExp(payload.server_dh_public, client_dh_private, DH_P);
            
            // 4. Derivar clave de sesión con SHA-256
            mbedtls_sha256((const unsigned char*)&shared_secret, sizeof(shared_secret), aes_key, 0);
            Serial.println("[OK] Clave de sesion AES-256-GCM establecida con exito.");
            
            imprimirMenu();
        }
    } else {
        Serial.println("Error: No se pudo conectar al servidor.");
    }
}

void loop() {
    if (client.connected()) {
        if (Serial.available()) {
            char opcion = Serial.read();
            while (Serial.available()) Serial.read(); // Limpiar salto de línea

            if (opcion == '1') enviarMensaje("Temp: 24.5C | Hum: 60% | Nodo Activo", 1);
            else if (opcion == '2') enviarMensaje("Temp: 24.5C | Hum: 60% | Nodo Activo", 2);
            else if (opcion == '3') enviarMensaje("Temp: 24.5C | Hum: 60% | Nodo Activo", 3);
            else if (opcion == '4') enviarMensaje("Temp: 24.5C | Hum: 60% | Nodo Activo", 4);
            else if (opcion == '5') enviarMensaje("Temp: 24.5C | Hum: 60% | Nodo Activo", 5);
        }
    } else {
        Serial.println("Desconectado del servidor.");
        delay(5000);
    }
}