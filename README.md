# Secure Wireless Messaging for IoT Devices

**Proyecto 1 · Criptografía · Universidad Yachay Tech**
Autores: Bryan Amaya, Christopher Ortiz

Sistema de mensajería segura entre dispositivos **ESP32**, sin servidor, sobre una red WiFi a la que se trata como **no confiable**. Toda la seguridad sale del protocolo criptográfico, no del medio.

| Propiedad | Mecanismo |
|---|---|
| Confidencialidad | AES-256-GCM |
| Integridad y autenticidad del mensaje | Tag de GCM; toda la cabecera va como datos asociados (AAD) |
| Autenticación de dispositivos | Firmas ECDSA P-256, una clave privada por dispositivo |
| Protección contra replay | SEQ creciente + SID por sesión + cadena de claves |
| Secreto hacia adelante | Diffie-Hellman efímero + clave distinta por mensaje |

El informe técnico completo (diagramas, ecuaciones, resultados) está en [`informe/`](informe/).

---

## Contenido del repositorio

```
nodo_p2p/nodo_p2p.ino    Firmware de las placas (el mismo archivo para todas)
tools/nodo_pc.py         Nodo simulado en el PC + gestión de claves
tools/atacante.py        Dispositivo D: ataques para las pruebas de seguridad
informe/main.tex         Informe en formato IEEE (ieeetj.cls)
legacy/                  Prototipo inicial (servidor, DH de 31 bits). Solo historial
```

> `legacy/` guarda `server.cpp` y `Client(ESP-32).cpp`, el primer prototipo con servidor.
> Se descartó porque su Diffie-Hellman de 31 bits se rompe en milisegundos y porque
> la consigna prohíbe algoritmos propios. **No forma parte de la solución final.**

---

## Arquitectura

```
        ┌──────────────── Red WiFi 2.4 GHz (NO confiable) ────────────────┐
        │                                                                  │
        │   Nodo A            sesión K_AB            Nodo B                │
        │   ESP32  ◄───────────────────────────────► ESP32                 │
        │      ▲                                        ▲                  │
        │      │ K_AC                            K_BC   │                  │
        │      └────────────►  Nodo C  ◄────────────────┘                  │
        │                 (PC, Python, simulado)                           │
        └──────────────────────────────────────────────────────────────────┘
                                   ▲
                       Nodo D (atacante.py): escucha, modifica,
                       reenvía, inyecta, suplanta
```

- **No hay servidor.** Cada nodo escucha en **TCP 8080** y anuncia su ID por **UDP broadcast 8081**. El anuncio no lleva secretos ni se confía en él; solo dice a dónde intentar la conexión.
- Cada par de dispositivos tiene su **propia sesión y sus propias claves**: lo que A le manda a B no lo puede descifrar C.
- Inicia la conexión la placa cuyo ID va antes en orden alfabético. El nodo del PC inicia hacia todas las placas que descubre.
- El **nodo C** existe porque solo hay dos placas físicas: permite mostrar tres dispositivos legítimos.

---

## Diseño criptográfico

Toda la criptografía viene de **mbedTLS** (placas) y de la librería **`cryptography`** de Python (PC). No hay algoritmos propios.

| Función | Primitiva |
|---|---|
| Clave de sesión | Diffie-Hellman, grupo MODP 2048 bits (RFC 3526 grupo 14), exponente de 256 bits, **nuevo en cada sesión** |
| Autenticación | ECDSA P-256 sobre el transcript completo del handshake |
| Derivación de claves | HKDF-SHA256 |
| Cifrado | AES-256-GCM (nonce de 96 bits, tag de 128 bits) |
| Evolución de claves | Cadena HKDF: una clave nueva por mensaje |

### Handshake

```
Iniciador I                                          Respondedor R
   │── (1) Hello: ID_I, N_I, Y_I ─────────────────────────►│  ¿ID_I autorizado? si no → cierra
   │◄── (2) status, ID_R, N_R, Y_R, SIG_R ─────────────────│  firma el transcript T
   │  verifica SIG_R con la clave pública GRABADA de R     │
   │── (3) SIG_I ──────────────────────────────────────────►│  verifica SIG_I con la pública de I
   │◄── (4) resultado ──────────────────────────────────────│
   │                                                        │
   │  z = g^(x_I·x_R) mod p ; HKDF(N_I‖N_R, z, "P1-KEYS"‖T)
   │  → CK_I→R , CK_R→I , SID
```

- `T = SHA256(Hello ‖ ID_R ‖ N_R ‖ Y_R)`: cubre ambos IDs, ambos nonces y ambos valores DH. Una firma solo vale para **este** handshake y **estas** identidades.
- Cada dispositivo guarda las claves **públicas** de los demás y verifica con esas, nunca con una recibida por la red.
- Robar una placa permite suplantar **solo a esa placa**.

### Cadena de claves por mensaje

```
MK_n     = HKDF(CK_n, "P1-MSG")      clave para cifrar el mensaje n
CK_(n+1) = HKDF(CK_n, "P1-CHAIN")    el estado avanza; CK_n se borra
```

Conocer `MK_n` no revela `CK_n` ni otras claves de mensaje; conocer `CK_n` no revela claves de mensajes anteriores. **No** hay seguridad post-compromiso: quien obtenga `CK_n` puede derivar las claves siguientes hasta el próximo handshake.

El receptor solo avanza su cadena **después** de autenticar el mensaje, así que un paquete forjado no desincroniza la sesión.

### Formato del paquete de datos

`ID_S ‖ SID ‖ SEQ ‖ N ‖ C ‖ TAG`, enteros en little endian.

| Offset | Bytes | Campo | Protección |
|---:|---:|---|---|
| 0 | 1 | tipo de trama (`0x01` datos, `0x02` ACK) | ninguna |
| 1 | 20 | `ID_S`, remitente | AAD |
| 21 | 4 | `SID`, identificador de sesión | AAD |
| 25 | 4 | `SEQ`, número de secuencia | AAD |
| 29 | 12 | `N`: 8 bytes aleatorios ‖ SEQ | AAD y nonce de GCM |
| 41 | 2 | `Len`, longitud de `C` | AAD |
| 43 | n | `C`, texto cifrado (n ≤ 1024) | cifrado + tag |
| 43+n | 16 | `TAG` | tag de GCM |

Overhead fijo: **58 bytes** por mensaje (42 de cabecera + 16 de tag), más 1 del tipo de trama.

---

## Requisitos

- 2 × **ESP32 Dev Module** y una red WiFi de **2.4 GHz** (el ESP32 no ve redes de 5 GHz). Todos los dispositivos, incluida la laptop, deben estar en la misma red.
- **Arduino IDE** con el core de ESP32 (se usó la versión 3.3.12).
- **Python 3** y `pip install cryptography` (para `nodo_pc.py` y para el modo `miembro` de `atacante.py`).

---

## Puesta en marcha

### 1. Generar las claves (cada dueño genera SOLO las suyas)

La clave privada nunca sale del equipo de su dueño; solo se intercambian las públicas.

```powershell
cd tools

# Bryan: su placa y el nodo simulado de su laptop
python nodo_pc.py --genkey ESP32_Bryan ESP32_Demian

# Christopher, en SU equipo
python nodo_pc.py --genkey ESP32_Christopher
```

Cada `--genkey` crea `keys/<ID>.key` (**privada**) y agrega la pública a `keys/authorized.txt`. Imprime la línea que hay que compartir con los demás:

```powershell
# Cada uno corre la línea PÚBLICA que recibe del otro:
python nodo_pc.py --addpub ESP32_Christopher=04...
python nodo_pc.py --addpub ESP32_Bryan=04...
python nodo_pc.py --addpub ESP32_Demian=04...

# Imprime el bloque AUTORIZADOS para el .ino (debe salir IGUAL en todos)
python nodo_pc.py --block
```

Tamaños: clave privada 256 bits (64 caracteres hex); clave pública 520 bits (130 caracteres hex, empieza con `04`).

### 2. Configurar el firmware

En `nodo_p2p/nodo_p2p.ino`, bloque `CONFIGURACIÓN`:

```cpp
const char* WIFI_SSID   = "TU_RED_2.4GHz";
const char* WIFI_PASS   = "TU_PASSWORD";
const char* MY_ID       = "ESP32_Bryan";          // distinto en cada placa (máx. 19 caracteres)
const char* MY_PRIV_HEX = "...";                  // SOLO la privada de ESTA placa
const Autorizado AUTORIZADOS[] = { ... };         // bloque de --block, igual en todas
```

### 3. Subir y comprobar

Abre el Monitor Serie a **115200 baudios**. Al arrancar cada placa imprime la **huella** de la clave pública de cada dispositivo autorizado. Las dos placas deben mostrar **las mismas huellas**; si no, tienen listas distintas.

Luego se descubren y aparece `==== Clave de sesion establecida con ... ====`. El handshake tarda del orden de **1 segundo** (cuatro exponenciaciones de 2048 bits y dos firmas ECDSA con sus verificaciones).

### 4. Nodo simulado en el PC

```powershell
python nodo_pc.py --id ESP32_Demian --ip <IP_WiFi_de_tu_laptop>
```

Opciones útiles: `--peer ESP32_Bryan=192.168.1.32` (fija una IP a mano si el descubrimiento falla), `--keydir` (carpeta de claves) y `--quiet`.

### Comandos del Monitor Serie (y de `nodo_pc.py`)

| Entrada | Acción |
|---|---|
| `texto` | cifra y envía a todas las placas conectadas |
| `@ID texto` | envía solo a una placa |
| `1` | mensaje de prueba normal |
| `2` | prueba: altera 1 byte del texto cifrado |
| `3` | prueba: altera 1 byte del tag |
| `4` | prueba: retransmite el último paquete aceptado (replay) |
| `5` | prueba: falsifica el remitente (`ID_S`) |
| `6` | prueba: paquete cifrado con una clave que no es la de la sesión |
| `p` | estado de las placas |
| `k` | estado de las cadenas de claves |
| `m` | menú |

Con `VERBOSE = true` (por defecto) cada nodo imprime `g` y `p`, las claves DH, el secreto compartido, las claves de sesión y, por mensaje: plaintext, ciphertext, tag, clave del mensaje y plaintext recuperado. Las líneas largas se imprimen en bloques de 64 caracteres.

---

## Pruebas de seguridad

Desde la laptop, en la misma red, contra la IP de una placa:

```powershell
python atacante.py <IP_placa> no-autorizado
python atacante.py <IP_placa> suplantar ESP32_Christopher
python atacante.py <IP_placa> miembro ESP32_Christopher ESP32_Demian
python atacante.py <IP_placa> inyectar
```

| # | Escenario | Cómo se prueba | Lo rechaza |
|---|---|---|---|
| T1 | Intercambio normal | `1` o texto libre | — (aceptado) |
| T2 | Texto cifrado alterado | `2` | tag de GCM |
| T3 | Tag alterado | `3` | tag de GCM |
| T4 | Replay de un paquete aceptado | `4` justo después de un mensaje aceptado | SEQ y cadena de claves |
| T5 | Remitente falsificado | `5` | chequeo de ID y AAD |
| T6 | Paquete con clave falsa | `6` | tag de GCM |
| T7 | Dispositivo fuera de la lista | `atacante.py ... no-autorizado` | lista de autorizados |
| T8 | ID válido sin su clave privada | `atacante.py ... suplantar <ID>` | firma `SIG_I` |
| T9 | Datos sin handshake | `atacante.py ... inyectar` | parser del handshake |
| T10 | Clave válida de un dispositivo usada para fingir ser otro | `atacante.py ... miembro <ID_que_finge> <ID_de_la_clave>` | firma contra la pública grabada |

En T7 a T10 la placa imprime un `[ALERTA]` con el intento y cierra la conexión. En T2 a T6 el emisor ve `RECHAZADO` en el ACK y el receptor imprime la razón técnica.

**Orden recomendado para una demostración:**

1. Mensajes normales y `k` para mostrar cómo cambia la clave en cada uno.
2. `4` justo después de un mensaje aceptado.
3. `6`, que no rompe la sesión.
4. Los cuatro modos de `atacante.py`.
5. **Reiniciar las placas antes de probar `2`, `3` o `5`**: estas pruebas alteran el paquete después de que el emisor ya avanzó su cadena, así que las dos cadenas quedan distintas y la sesión debe rehacerse. Es un efecto de probar desde el lado del emisor, no de un ataque externo.

---

## Resultados

Medidos en dos ESP32 con el firmware final (`VERBOSE` activado):

| Métrica | Resultado |
|---|---|
| Cifrado AES-GCM, 36 B | ≈ 202 µs (n = 13) |
| Cifrado AES-GCM, 173 B | 272 µs (n = 1) |
| Descifrado + verificación (aceptado) | ≈ 200 µs (n = 3) |
| Paquete descartado por replay o ID | 5 a 8 µs |
| Overhead por mensaje | 58 B fijos |
| Handshake (iniciador) | típico ≈ 1.2 s; también 3.4 s y 15.0 s en dos corridas |
| Round trip del ACK (aceptados) | mediana 65 ms (46 a 677 ms, n = 11) |

El cifrado pesa ≈ 0.3 % del round trip: la latencia la domina la red. El round trip incluye la salida por consola del receptor y no se aisló. Las muestras son pocas, así que son órdenes de magnitud y no promedios precisos. El handshake con HMAC de una revisión anterior tardaba 189 ms; la diferencia se atribuye a las firmas ECDSA por software.

---

## Limitaciones

- **Distribución manual de claves públicas** y sin revocación: agregar o quitar un dispositivo obliga a reprogramar todas las placas.
- La clave privada queda compilada en el firmware y no está activado el cifrado de flash: robar una placa revela su clave (y permite suplantar solo a esa placa).
- **Sin seguridad post-compromiso**: ver la cadena de claves.
- La cadena es estrictamente secuencial: un paquete auténtico perdido o reordenado desincroniza la sesión y exige un nuevo handshake. TCP entrega en orden, así que es raro.
- Los ACK, el byte de tipo de trama y los anuncios de descubrimiento no están autenticados. Falsificarlos puede molestar una conexión, pero no hace que un receptor acepte un mensaje.
- Un respondedor calcula un par DH y una firma antes de que el iniciador pruebe su identidad, y los IDs son públicos: una inundación de `Hello` podría agotar una placa. No hay limitación de tasa.
- Las longitudes de los mensajes y quién habla con quién son visibles.
- No hay verificación formal ni análisis de canales laterales.

---

## Seguridad del repositorio

**No subas a GitHub** (el repositorio es público):

- `keys/` y cualquier archivo `*.key`: contienen claves **privadas**.
- Un `.ino` con `MY_PRIV_HEX` o la contraseña del WiFi puestos. Sube solo la versión con los placeholders.

Agrega esto a `.gitignore`:

```
keys/
*.key
```

El bloque `AUTORIZADOS` (claves públicas) sí es público.

---

## Solución de problemas

| Síntoma | Causa probable |
|---|---|
| La placa imprime solo puntos | Red de 5 GHz o `WIFI_SSID` mal escrito. Usa una red de 2.4 GHz. |
| `MY_PRIV_HEX no es una clave privada valida` | Falta pegar la privada, o no mide 64 caracteres hex. |
| `MY_PRIV_HEX no corresponde a la clave publica de este MY_ID` | `MY_ID` no es el de esa clave, o la lista `AUTORIZADOS` no es la que generó `--genkey`. |
| Las huellas difieren entre placas | Listas `AUTORIZADOS` distintas. Vuelve a correr `--block` y pega el mismo bloque en todas. |
| Se descubren pero no abren sesión | El router aísla a los clientes entre sí. Prueba con el hotspot de un celular en 2.4 GHz. |
| El nodo del PC no encuentra las placas | Laptop y placas en subredes distintas (por ejemplo, la laptop en 5 GHz). Revisa `ipconfig` o usa `--peer`. |
| `RECHAZADO` en todo después de una prueba `2`, `3` o `5` | Es esperado: las cadenas quedaron desincronizadas. Reinicia las placas. |
| `nodo_pc.py --genkey` dice que la clave ya existe | Protección para no pisar tus claves. Usa `--force` solo si vas a reprogramar todas las placas. |

---

## Referencias

- RFC 3526: grupos MODP de Diffie-Hellman · RFC 5869: HKDF
- NIST FIPS 186-4: ECDSA · NIST SP 800-38D: AES-GCM
- The Double Ratchet Algorithm (Marlinspike y Perrin, Signal)
- [mbedTLS](https://github.com/Mbed-TLS/mbedtls) · [`cryptography`](https://cryptography.io)
