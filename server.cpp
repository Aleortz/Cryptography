#include <iostream>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <chrono>
#include <string>
#include <random>
#include <thread>
#include <mutex>
#include <map>

// --- Compatibilidad de sockets: MinGW nativo vs Cygwin/Linux/WSL ---
#if defined(_WIN32) && !defined(__CYGWIN__)
  #include <winsock2.h>
  #include <ws2tcpip.h>
  typedef SOCKET sock_t;
  #define CLOSE_SOCKET closesocket
  #define IS_WINDOWS_NATIVE 1
#else
  #include <sys/socket.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  #include <cerrno>
  typedef int sock_t;
  #define CLOSE_SOCKET close
  #define IS_WINDOWS_NATIVE 0
#endif

#include <openssl/evp.h>
#include <openssl/sha.h>

const uint64_t DH_P = 2147483647; 
const uint64_t DH_G = 16807;

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

// Estructura para guardar la sesión activa de cada ESP32
struct ClientSession {
    sock_t socket;
    std::string id;
    uint32_t sid;
    unsigned char aes_key[32];
    uint32_t out_seq = 1; // Contador de salida del servidor hacia este cliente
};

std::map<std::string, ClientSession*> active_clients;
std::mutex clients_mutex;

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

bool esDispositivoAutorizado(const char* id) {
    return (strcmp(id, "ESP32_Christopher") == 0 || strcmp(id, "ESP32_Bryan") == 0);
}

// Re-cifra y reenvía el mensaje verificado al otro ESP-32 conectado
void reenviarAlOtroNodo(const std::string& sender_id, const unsigned char* plaintext, uint16_t len) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    for (auto& pair : active_clients) {
        if (pair.first != sender_id) {
            ClientSession* dest = pair.second;
            
            PacketHeader fwd_hdr;
            memset(&fwd_hdr, 0, sizeof(fwd_hdr));
            strncpy(fwd_hdr.sender_id, sender_id.c_str(), sizeof(fwd_hdr.sender_id) - 1);
            fwd_hdr.session_id = dest->sid;
            fwd_hdr.seq_num = dest->out_seq++;
            fwd_hdr.cipher_len = len;

            std::random_device rd;
            uint32_t r1 = rd(), r2 = rd();
            memcpy(fwd_hdr.nonce, &r1, 4);
            memcpy(fwd_hdr.nonce + 4, &r2, 4);
            memcpy(fwd_hdr.nonce + 8, &fwd_hdr.seq_num, 4);

            unsigned char* fwd_cipher = new unsigned char[len];
            unsigned char fwd_tag[16];

            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
            EVP_EncryptInit_ex(ctx, NULL, NULL, dest->aes_key, fwd_hdr.nonce);

            int outlen;
            EVP_EncryptUpdate(ctx, NULL, &outlen, (const unsigned char*)&fwd_hdr, sizeof(PacketHeader));
            EVP_EncryptUpdate(ctx, fwd_cipher, &outlen, plaintext, len);
            EVP_EncryptFinal_ex(ctx, fwd_cipher + outlen, &outlen);
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, fwd_tag);
            EVP_CIPHER_CTX_free(ctx);

            // Avisamos con un byte '2' que viene un paquete reenviado antes de mandar la trama
            uint8_t frame_type = 2; 
            write_all(dest->socket, &frame_type, 1);
            write_all(dest->socket, &fwd_hdr, sizeof(PacketHeader));
            write_all(dest->socket, fwd_cipher, len);
            write_all(dest->socket, fwd_tag, 16);

            delete[] fwd_cipher;
            std::cout << "    [->] Mensaje enrutado de forma segura hacia " << dest->id << std::endl;
        }
    }
}

void manejarCliente(sock_t clientSocket) {
    std::random_device rd;
    char client_id[20] = {0};
    if (!read_exact(clientSocket, client_id, 20)) {
        CLOSE_SOCKET(clientSocket);
        return;
    }

    std::cout << "\n[+] Solicitud de conexion de: '" << client_id << "'" << std::endl;

    if (!esDispositivoAutorizado(client_id)) {
        std::cerr << "[ALERTA SEGURIDAD] Dispositivo '" << client_id << "' NO AUTORIZADO. Rechazando sesion." << std::endl;
        ServerHandshake reject_hs = { 0, 0, 0, 0, 0, 0 };
        write_all(clientSocket, &reject_hs, sizeof(ServerHandshake));
        CLOSE_SOCKET(clientSocket);
        return;
    }

    uint64_t p_rsa = 50021, q_rsa = 50023;
    uint64_t rsa_n = p_rsa * q_rsa;
    uint64_t phi = (p_rsa - 1) * (q_rsa - 1);
    uint64_t rsa_e = 65537;
    uint64_t rsa_d = modInverse(rsa_e, phi);

    uint32_t assigned_sid = rd();
    uint64_t server_dh_private = ((((uint64_t)rd()) << 32) | rd()) % (DH_P - 2) + 1;
    uint64_t server_dh_public = modExp(DH_G, server_dh_private, DH_P);
    uint64_t signature = modExp(server_dh_public, rsa_d, rsa_n);

    ServerHandshake handshake = { 1, assigned_sid, server_dh_public, signature, rsa_e, rsa_n };
    write_all(clientSocket, &handshake, sizeof(ServerHandshake));

    uint64_t client_dh_public = 0;
    if (!read_exact(clientSocket, &client_dh_public, sizeof(uint64_t))) {
        CLOSE_SOCKET(clientSocket);
        return;
    }

    uint64_t shared_secret = modExp(client_dh_public, server_dh_private, DH_P);
    
    ClientSession* session = new ClientSession();
    session->socket = clientSocket;
    session->id = client_id;
    session->sid = assigned_sid;
    SHA256((const unsigned char*)&shared_secret, sizeof(shared_secret), session->aes_key);

    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        active_clients[session->id] = session;
    }

    std::cout << "[OK] " << client_id << " autenticado. SID: 0x" << std::hex << assigned_sid << std::dec << std::endl;
    std::cout << "[OK] Clave AES-256 derivada para " << client_id << ". Esperando paquetes...\n" << std::endl;

    uint32_t last_valid_seq = 0;

    while (true) {
        PacketHeader hdr;
        if (!read_exact(clientSocket, &hdr, sizeof(PacketHeader))) break;

        unsigned char* ciphertext = new unsigned char[hdr.cipher_len];
        unsigned char tag[16];

        if (!read_exact(clientSocket, ciphertext, hdr.cipher_len) || !read_exact(clientSocket, tag, 16)) {
            delete[] ciphertext;
            break;
        }

        auto t_start = std::chrono::high_resolution_clock::now();
        bool packet_valid = true;
        std::string razon_rechazo = "";

        if (strcmp(hdr.sender_id, client_id) != 0) {
            packet_valid = false;
            razon_rechazo = "Suplantacion de Sender ID (ID_S no coincide con la sesion)";
        } else if (hdr.session_id != assigned_sid) {
            packet_valid = false;
            razon_rechazo = "Session ID (SID) invalido";
        } else if (hdr.seq_num <= last_valid_seq) {
            packet_valid = false;
            razon_rechazo = "Replay Attack detectado (SEQ repetido/antiguo: " + std::to_string(hdr.seq_num) + ")";
        }

        unsigned char* plaintext = new unsigned char[hdr.cipher_len + 1];
        if (packet_valid) {
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
            EVP_DecryptInit_ex(ctx, NULL, NULL, session->aes_key, hdr.nonce);

            int outlen;
            EVP_DecryptUpdate(ctx, NULL, &outlen, (const unsigned char*)&hdr, sizeof(PacketHeader));
            EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, hdr.cipher_len);
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);

            int ret = EVP_DecryptFinal_ex(ctx, plaintext + outlen, &outlen);
            EVP_CIPHER_CTX_free(ctx);

            if (ret <= 0) {
                packet_valid = false;
                razon_rechazo = "Fallo de autenticacion GCM (Ciphertext, Header o TAG adulterado)";
            }
        }

        auto t_end = std::chrono::high_resolution_clock::now();
        auto t_dec_us = std::chrono::duration_cast<std::chrono::microseconds>(t_end - t_start).count();

        uint8_t ack = packet_valid ? 1 : 0;
        write_all(clientSocket, &ack, 1);

        if (packet_valid) {
            last_valid_seq = hdr.seq_num;
            plaintext[hdr.cipher_len] = '\0';
            std::cout << "[ACEPTADO | SEQ: " << hdr.seq_num << " | Dec+Verif: " << t_dec_us << " us] "
                      << hdr.sender_id << ": \"" << plaintext << "\"" << std::endl;
            
            // Reenviar al otro ESP-32 si está conectado
            reenviarAlOtroNodo(session->id, plaintext, hdr.cipher_len);
        } else {
            std::cerr << "[RECHAZADO | SEQ: " << hdr.seq_num << " | Tiempo: " << t_dec_us << " us] "
                      << "Motivo: " << razon_rechazo << std::endl;
        }

        delete[] ciphertext;
        delete[] plaintext;
    }

    std::cout << "\n[!] Conexion finalizada con " << client_id << std::endl;
    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        active_clients.erase(session->id);
    }
    delete session;
    CLOSE_SOCKET(clientSocket);
}

int main() {
#if IS_WINDOWS_NATIVE
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    sock_t serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY); 
    serverAddr.sin_port = htons(8080);       

    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) != 0) {
        std::cerr << "Error en bind puerto 8080." << std::endl;
        return 1;
    }

    listen(serverSocket, 5);
    std::cout << "=== SERVIDOR CRIPTOGRAFICO IOT MULTICLIENTE (PUERTO 8080) ===" << std::endl;

    while (true) {
        sockaddr_in clientAddr;
        socklen_t clientSize = sizeof(clientAddr);
        sock_t clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientSize);
        if (clientSocket >= 0) {
            std::thread t(manejarCliente, clientSocket);
            t.detach(); // Atender a cada ESP32 en su propio hilo paralelo
        }
    }

    CLOSE_SOCKET(serverSocket);
    return 0;
}