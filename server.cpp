#include <iostream>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <chrono>
#include <string>
#include <random>

// --- Compatibilidad de sockets: Windows (Code::Blocks/MinGW) y Linux/WSL ---
#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  typedef SOCKET sock_t;
  #define CLOSE_SOCKET closesocket
#else
  #include <sys/socket.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  typedef int sock_t;
  #define CLOSE_SOCKET close
#endif
#include <openssl/evp.h>
#include <openssl/sha.h>

const uint64_t DH_P = 2147483647; 
const uint64_t DH_G = 16807;

// Estructuras idénticas al ESP-32
// #pragma pack se respeta igual en MinGW y en Linux (en MinGW, __attribute__((packed))
// puede no dar el mismo layout que en el ESP32)
#pragma pack(push, 1)
struct ServerHandshake {
    uint8_t auth_status;
    uint32_t session_id;
    uint64_t server_dh_public;
    uint64_t rsa_signature;
    uint64_t rsa_e; 
    uint64_t rsa_n; 
};

struct PacketHeader {
    char sender_id[20];
    uint32_t session_id;
    uint32_t seq_num;
    uint8_t nonce[12];
    uint16_t cipher_len;
};
#pragma pack(pop)
static_assert(sizeof(ServerHandshake) == 37, "ServerHandshake debe medir 37 bytes como en el ESP32");
static_assert(sizeof(PacketHeader) == 42, "PacketHeader debe medir 42 bytes como en el ESP32");

// --- Funciones Matemáticas Core ---
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

uint64_t modInverse(uint64_t a, uint64_t m) {
    int64_t m0 = m, t, q;
    int64_t x0 = 0, x1 = 1;
    if (m == 1) return 0;
    while (a > 1) {
        q = a / m; t = m;
        m = a % m, a = t; t = x0;
        x0 = x1 - q * x0; x1 = t;
    }
    if (x1 < 0) x1 += m0;
    return x1;
}

bool read_exact(sock_t sock, void* buffer, size_t size) {
    size_t total_read = 0;
    char* ptr = (char*)buffer;
    while (total_read < size) {
        int n = recv(sock, ptr + total_read, (int)(size - total_read), 0);
        if (n <= 0) return false;
        total_read += n;
    }
    return true;
}

void write_all(sock_t sock, const void* buffer, size_t size) {
    send(sock, (const char*)buffer, (int)size, 0);
}

// Lista blanca de dispositivos IoT autorizados (Requisito Sección 2 y 4)
bool esDispositivoAutorizado(const char* id) {
    return (strcmp(id, "ESP32_Christopher") == 0 || strcmp(id, "ESP32_Bryan") == 0);
}

int main() {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cerr << "Error inicializando Winsock" << std::endl;
        return 1;
    }
#endif
    // En Windows rand() solo da 15 bits (RAND_MAX = 32767); usamos random_device
    std::random_device rd;

    sock_t serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY; 
    serverAddr.sin_port = htons(8080);       

    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) != 0) {
        std::cerr << "Error: no se pudo abrir el puerto 8080 (ya esta en uso?)" << std::endl;
        return 1;
    }
    listen(serverSocket, 3);
    std::cout << "=== SERVIDOR CRIPTOGRAFICO IOT (PUERTO 8080) ===" << std::endl;

    sockaddr_in clientAddr;
    socklen_t clientSize = sizeof(clientAddr);
    sock_t clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientSize);
    
    // 1. Verificar Autenticidad del Dispositivo
    char client_id[20] = {0};
    read_exact(clientSocket, client_id, 20);
    std::cout << "\n[+] Solicitud de conexion de: '" << client_id << "'" << std::endl;

    uint64_t p_rsa = 50021, q_rsa = 50023;
    uint64_t rsa_n = p_rsa * q_rsa;
    uint64_t phi = (p_rsa - 1) * (q_rsa - 1);
    uint64_t rsa_e = 65537;
    uint64_t rsa_d = modInverse(rsa_e, phi);

    uint32_t assigned_sid = rd();
    uint64_t server_dh_private = ((((uint64_t)rd()) << 32) | rd()) % (DH_P - 2) + 1;
    uint64_t server_dh_public = modExp(DH_G, server_dh_private, DH_P);
    uint64_t signature = modExp(server_dh_public, rsa_d, rsa_n);

    if (!esDispositivoAutorizado(client_id)) {
        std::cerr << "[ALERTA SEGURIDAD] Dispositivo '" << client_id << "' NO AUTORIZADO. Rechazando sesion." << std::endl;
        ServerHandshake reject_hs = { 0, 0, 0, 0, 0, 0 };
        write_all(clientSocket, &reject_hs, sizeof(ServerHandshake));
        CLOSE_SOCKET(clientSocket);
        CLOSE_SOCKET(serverSocket);
        return 0;
    }

    // 2. Enviar Handshake Autorizado
    ServerHandshake handshake = { 1, assigned_sid, server_dh_public, signature, rsa_e, rsa_n };
    write_all(clientSocket, &handshake, sizeof(ServerHandshake));

    uint64_t client_dh_public = 0;
    read_exact(clientSocket, &client_dh_public, sizeof(uint64_t));

    uint64_t shared_secret = modExp(client_dh_public, server_dh_private, DH_P);
    unsigned char aes_key[32];
    SHA256((const unsigned char*)&shared_secret, sizeof(shared_secret), aes_key);

    std::cout << "[OK] Dispositivo autenticado. SID asignado: 0x" << std::hex << assigned_sid << std::dec << std::endl;
    std::cout << "[OK] Clave de sesion derivada (SHA-256). Esperando paquetes...\n" << std::endl;

    uint32_t last_valid_seq = 0;

    // --- BUCLE DE RECEPCIÓN, VALIDACIÓN Y MÉTRICAS ---
    while (true) {
        PacketHeader hdr;
        if (!read_exact(clientSocket, &hdr, sizeof(PacketHeader))) break;

        unsigned char* ciphertext = new unsigned char[hdr.cipher_len];
        unsigned char tag[16];

        if (!read_exact(clientSocket, ciphertext, hdr.cipher_len)) break;
        if (!read_exact(clientSocket, tag, 16)) break;

        // Medición de tiempo de descifrado y verificación (Sección 5)
        auto t_start = std::chrono::high_resolution_clock::now();

        bool packet_valid = true;
        std::string razon_rechazo = "";

        // A. Verificar Identidad del Remitente y Sesión
        if (strcmp(hdr.sender_id, client_id) != 0) {
            packet_valid = false;
            razon_rechazo = "Suplantacion de Sender ID (ID_S no coincide con la sesion)";
        } else if (hdr.session_id != assigned_sid) {
            packet_valid = false;
            razon_rechazo = "Session ID (SID) invalido o desconocido";
        } 
        // B. Verificar Protección contra Replay (Secuencia estrictamente creciente)
        else if (hdr.seq_num <= last_valid_seq) {
            packet_valid = false;
            razon_rechazo = "Replay Attack detectado (Numero de secuencia repetido o antiguo: " + std::to_string(hdr.seq_num) + ")";
        }

        // C. Descifrado Autenticado AES-256-GCM (Verifica integridad de Header + Ciphertext)
        unsigned char* plaintext = new unsigned char[hdr.cipher_len + 1];
        if (packet_valid) {
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
            EVP_DecryptInit_ex(ctx, NULL, NULL, aes_key, hdr.nonce);

            int outlen;
            // Inyectar la cabecera como AAD para verificar que ningún campo (ID_S, SID, SEQ, N) fue modificado
            EVP_DecryptUpdate(ctx, NULL, &outlen, (const unsigned char*)&hdr, sizeof(PacketHeader));
            // Descifrar payload
            EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, hdr.cipher_len);
            // Verificar TAG
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);

            int ret = EVP_DecryptFinal_ex(ctx, plaintext + outlen, &outlen);
            EVP_CIPHER_CTX_free(ctx);

            if (ret <= 0) {
                packet_valid = false;
                razon_rechazo = "Fallo de autenticacion GCM (Ciphertext, Header o TAG adulterado en transito)";
            }
        }

        auto t_end = std::chrono::high_resolution_clock::now();
        auto t_dec_us = std::chrono::duration_cast<std::chrono::microseconds>(t_end - t_start).count();

        // Responder ACK (1 = Aceptado, 0 = Rechazado) para medir RTT en el ESP-32
        uint8_t ack = packet_valid ? 1 : 0;
        write_all(clientSocket, &ack, 1);

        if (packet_valid) {
            last_valid_seq = hdr.seq_num; // Actualizar contador anti-replay solo si el paquete es íntegro
            plaintext[hdr.cipher_len] = '\0';
            std::cout << "[ACEPTADO | SEQ: " << hdr.seq_num << " | Dec+Verif: " << t_dec_us << " us] "
                      << hdr.sender_id << ": \"" << plaintext << "\"" << std::endl;
        } else {
            std::cerr << "[RECHAZADO | SEQ: " << hdr.seq_num << " | Tiempo: " << t_dec_us << " us] "
                      << "Motivo: " << razon_rechazo << std::endl;
        }

        delete[] ciphertext;
        delete[] plaintext;
    }

    std::cout << "\n[!] Conexion finalizada." << std::endl;
    CLOSE_SOCKET(clientSocket);
    CLOSE_SOCKET(serverSocket);
#ifdef _WIN32
    WSACleanup();
    system("pause");  // que la consola de Code::Blocks no se cierre sola
#endif
    return 0;
}