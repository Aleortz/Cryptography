#include <WiFi.h>
#include <cstdint>
#include "mbedtls/gcm.h"
#include "mbedtls/sha256.h"

// --- Configuración de Red e Identidad ---
const char* ssid = "YACHAYTECH";
const char* password = ""; 
const char* host_servidor = "172.23.195.160"; // IP de la laptop donde corre el servidor
const uint16_t puerto = 8080;

// CAMBIAR A "ESP32_Bryan" EN EL SEGUNDO ESP32
const char* CLIENT_ID = "ESP32_Christopher"; 

WiFiClient client;

// --- Parámetros Públicos Diffie-Hellman ---
const uint64_t DH_P = 2147483647; 
const uint64_t DH_G = 16807;

// --- Estructuras de Protocolo ---
// 37 bytes exactos (idéntico al servidor)
struct __attribute__((packed)) ServerHandshake {
    uint8_t auth_status;       // 1 = Autorizado, 0 = No autorizado, 2 = Nombre duplicado
    uint32_t session_id;       // SID asignado por el servidor
    uint64_t server_dh_public;
    uint64_t rsa_signature;
    uint64_t rsa_e; 
    uint64_t rsa_n; 
};

// 42 bytes exactos: ID_S || SID || SEQ || N || Len (Autenticado como AAD en GCM)
struct __attribute__((packed)) PacketHeader {
    char sender_id[20];
    uint32_t session_id;
    uint32_t seq_num;
    uint8_t nonce[12];
    uint16_t cipher_len;
};

// --- Variables de Estado Criptográfico ---
uint8_t aes_key[32];
uint32_t current_sid = 0;
uint32_t sequence_counter = 1;
uint32_t last_rx_seq = 0;

// Función auxiliar para imprimir bytes en Hexadecimal
void imprimirHex(const unsigned char* buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        Serial.printf("%02X ", buf[i]);
    }
    Serial.println();
}

// --- Funciones Matemáticas Core (Handshake RSA + DH) ---
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

// --- Función de Envío, Cifrado y Pruebas de Seguridad ---
void enviarMensaje(const char* texto, int modo_ataque) {
    if (!client.connected()) return;

    size_t msg_len = strlen(texto);
    PacketHeader hdr;
    memset(&hdr, 0, sizeof(hdr));
    strncpy(hdr.sender_id, CLIENT_ID, sizeof(hdr.sender_id) - 1);
    hdr.session_id = current_sid;

    // Si es Replay Attack (modo 4), repite el SEQ anterior
    if (modo_ataque == 4 && sequence_counter > 1) {
        hdr.seq_num = sequence_counter - 1;
    } else {
        hdr.seq_num = sequence_counter++;
    }

    // Construir Nonce de 12 bytes: 8 bytes aleatorios por hardware (TRNG) + 4 bytes de SEQ
    uint32_t rand1 = esp_random();
    uint32_t rand2 = esp_random();
    memcpy(hdr.nonce, &rand1, 4);
    memcpy(hdr.nonce + 4, &rand2, 4);
    memcpy(hdr.nonce + 8, &hdr.seq_num, 4);
    hdr.cipher_len = msg_len;

    unsigned char ciphertext[msg_len];
    unsigned char tag[16];

    // Medir tiempo de cifrado
    unsigned long t_start_enc = micros();

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, aes_key, 256);

    // Cifrar e incluir PacketHeader como AAD (protege ID_S, SID, SEQ y Nonce)
    mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, msg_len,
                              hdr.nonce, sizeof(hdr.nonce),
                              (const unsigned char*)&hdr, sizeof(PacketHeader),
                              (const unsigned char*)texto, ciphertext,
                              sizeof(tag), tag);
    mbedtls_gcm_free(&gcm);

    unsigned long t_enc = micros() - t_start_enc;

    // Simulación de escenarios de ataque (Sección 4)
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

    // Transmitir paquete y medir latencia (RTT)
    unsigned long t_start_net = micros();

    client.write((const uint8_t*)&hdr, sizeof(PacketHeader));
    client.write(ciphertext, msg_len);
    client.write(tag, sizeof(tag));

    uint8_t ack = 0;
    readExact(client, &ack, 1);
    unsigned long t_latency = micros() - t_start_net;

    size_t total_packet_size = sizeof(PacketHeader) + msg_len + sizeof(tag);

    // Mostrar resultados y métricas (Sección 5)
    Serial.println("==========================================");
    Serial.printf("[%s - ENVIO] (SEQ: %u | SID: 0x%08X)\n", CLIENT_ID, hdr.seq_num, hdr.session_id);
    Serial.printf(" -> 1. Texto a cifrar (Plaintext): \"%s\"\n", texto);
    Serial.print(" -> 2. Texto cifrado (Ciphertext HEX): ");
    imprimirHex(ciphertext, msg_len);
    Serial.printf(" -> 3. Tamano Plaintext: %u bytes | Paquete Protegido: %u bytes\n", msg_len, total_packet_size);
    Serial.printf(" -> 4. Tiempo de Cifrado (AES-GCM): %lu us\n", t_enc);
    Serial.printf(" -> 5. Latencia de Comunicacion (RTT): %lu us (%.2f ms)\n", t_latency, t_latency / 1000.0);
    Serial.printf(" -> 6. Estado en Servidor: %s\n", (ack == 1) ? "ACEPTADO (Integro)" : "RECHAZADO (Alerta MitM/Fallo)");
    Serial.println("==========================================\n");
}

void imprimirMenu() {
    Serial.println("\n--- MODO CHAT SEGURO Y PRUEBAS DE SEGURIDAD ---");
    Serial.println(" * Escribe cualquier mensaje en el Monitor Serie y presiona Enter para enviarlo.");
    Serial.println(" * O escribe uno de estos comandos para ejecutar pruebas de ataque:");
    Serial.println("   [!2] Test Integridad: Modificar Ciphertext (C)");
    Serial.println("   [!3] Test Autenticacion: Modificar TAG");
    Serial.println("   [!4] Test Replay Protection: Reenviar SEQ anterior");
    Serial.println("   [!5] Test Falsificacion: Alterar Sender ID (ID_S)");
    Serial.println("-----------------------------------------------\n");
}

void setup() {
    Serial.begin(115200);
    delay(1000);

    Serial.printf("\n==========================================\n");
    Serial.printf("Iniciando nodo IoT: %s\n", CLIENT_ID);
    Serial.printf("Parametros Diffie-Hellman -> p: %llu | g: %llu\n", DH_P, DH_G);
    Serial.printf("==========================================\n");

    WiFi.begin(ssid, password);
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    Serial.println("\nWi-Fi Conectado. IP local: " + WiFi.localIP().toString());

    client.setNoDelay(true);
    if (client.connect(host_servidor, puerto)) {
        // Enviar ID de 20 bytes fijos al servidor
        char id_buf[20] = {0};
        strncpy(id_buf, CLIENT_ID, 19);
        client.write((const uint8_t*)id_buf, 20);

        ServerHandshake payload;
        if (readExact(client, (uint8_t*)&payload, sizeof(ServerHandshake))) {
            if (payload.auth_status == 0) {
                Serial.println("[ERROR] Dispositivo NO AUTORIZADO por el servidor. Conexion rechazada.");
                client.stop();
                return;
            } else if (payload.auth_status == 2) {
                Serial.printf("[ERROR] Ya existe un dispositivo activo con el nombre '%s'. Conexion rechazada.\n", CLIENT_ID);
                client.stop();
                return;
            }

            if (!rsaVerify(payload.server_dh_public, payload.rsa_signature, payload.rsa_e, payload.rsa_n)) {
                Serial.println("[ALERTA MITM] Firma RSA del servidor invalida. Abortando.");
                client.stop();
                return;
            }

            current_sid = payload.session_id;
            
            // Generar par de claves Diffie-Hellman del cliente
            uint64_t client_dh_private = (esp_random() % (DH_P - 2)) + 1;
            uint64_t client_dh_public = modExp(DH_G, client_dh_private, DH_P);
            client.write((const uint8_t*)&client_dh_public, sizeof(uint64_t));

            // Calcular secreto compartido y derivar clave AES-256 con SHA-256
            uint64_t shared_secret = modExp(payload.server_dh_public, client_dh_private, DH_P);
            mbedtls_sha256((const unsigned char*)&shared_secret, sizeof(shared_secret), aes_key, 0);

            Serial.println("\n--- PARAMETROS CRIPTOGRAFICOS DE SESION ---");
            Serial.printf(" -> Nodo: %s | Session ID (SID): 0x%08X\n", CLIENT_ID, current_sid);
            Serial.printf(" -> Parametros DH: p = %llu, g = %llu\n", DH_P, DH_G);
            Serial.printf(" -> Clave Privada DH de %s (a): %llu\n", CLIENT_ID, client_dh_private);
            Serial.printf(" -> Clave Publica DH de %s (A = g^a mod p): %llu\n", CLIENT_ID, client_dh_public);
            Serial.printf(" -> Clave Publica DH Servidor (B): %llu\n", payload.server_dh_public);
            Serial.printf(" -> Secreto Compartido Derivado (K): %llu\n", shared_secret);
            Serial.println("-------------------------------------------");
            
            imprimirMenu();
        } else {
            Serial.println("Error: No se recibio el handshake completo del servidor.");
        }
    } else {
        Serial.println("Error: No se pudo conectar al puerto del servidor.");
    }
}

void loop() {
    if (client.connected()) {
        // 1. Escuchar si llegó un paquete reenviado desde el otro ESP32
        if (client.available()) {
            uint8_t frame_type = client.read();
            if (frame_type == 2) {
                PacketHeader rx_hdr;
                if (readExact(client, (uint8_t*)&rx_hdr, sizeof(PacketHeader))) {
                    unsigned char rx_cipher[rx_hdr.cipher_len];
                    unsigned char rx_tag[16];
                    readExact(client, rx_cipher, rx_hdr.cipher_len);
                    readExact(client, rx_tag, 16);

                    unsigned long t_start_dec = micros();
                    unsigned char rx_plain[rx_hdr.cipher_len + 1];
                    memset(rx_plain, 0, sizeof(rx_plain));

                    mbedtls_gcm_context gcm;
                    mbedtls_gcm_init(&gcm);
                    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, aes_key, 256);

                    int ret = mbedtls_gcm_auth_decrypt(&gcm, rx_hdr.cipher_len,
                                                       rx_hdr.nonce, sizeof(rx_hdr.nonce),
                                                       (const unsigned char*)&rx_hdr, sizeof(PacketHeader),
                                                       rx_tag, sizeof(rx_tag),
                                                       rx_cipher, rx_plain);
                    mbedtls_gcm_free(&gcm);
                    unsigned long t_dec = micros() - t_start_dec;

                    Serial.println("\n==========================================");
                    Serial.printf("[%s - RECEPCION] De: %s (SEQ: %u)\n", CLIENT_ID, rx_hdr.sender_id, rx_hdr.seq_num);
                    Serial.print(" -> 1. Texto Cifrado recibido (HEX): ");
                    imprimirHex(rx_cipher, rx_hdr.cipher_len);

                    if (ret == 0 && rx_hdr.session_id == current_sid && rx_hdr.seq_num > last_rx_seq) {
                        last_rx_seq = rx_hdr.seq_num;
                        rx_plain[rx_hdr.cipher_len] = '\0';
                        
                        Serial.print(" -> 2. TEXTO DESCIFRADO LEGIBLE: \"");
                        Serial.print((char*)rx_plain);
                        Serial.println("\"");
                        Serial.printf(" -> 3. Tiempo Descifrado + Verificacion GCM: %lu us\n", t_dec);
                    } else {
                        Serial.println(" -> [ALERTA] Paquete rechazado (Fallo de autenticacion GCM o Replay).");
                    }
                    Serial.println("==========================================\n");
                }
            }
        }

        // 2. Leer cualquier texto o comando de prueba desde el Monitor Serie
        if (Serial.available()) {
            String input = Serial.readStringUntil('\n');
            input.trim();

            if (input.length() > 0) {
                if (input == "!2") {
                    enviarMensaje("Prueba de alteracion de Ciphertext", 2);
                } else if (input == "!3") {
                    enviarMensaje("Prueba de alteracion de TAG", 3);
                } else if (input == "!4") {
                    enviarMensaje("Prueba de paquete repetido (Replay)", 4);
                } else if (input == "!5") {
                    enviarMensaje("Prueba de falsificacion de remitente", 5);
                } else {
                    // Cualquier otro texto que escribas se cifra y se envía al otro ESP32
                    enviarMensaje(input.c_str(), 1);
                }
            }
        }
    } else {
        Serial.println("Desconectado del servidor.");
        delay(5000);
    }
}