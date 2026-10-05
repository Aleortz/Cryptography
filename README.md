# Secure Wireless Messaging for IoT Devices

**Project 1 · Cryptography · Yachay Tech University**
Authors: Bryan Amaya, Christopher Ortiz

A secure messaging system between **ESP32** devices, with no server, over a Wi-Fi network that is treated as **untrusted**. All security comes from the cryptographic protocol, not from the medium.

| Property | Mechanism |
|---|---|
| Confidentiality | AES-256-GCM |
| Message integrity and authenticity | GCM tag; the whole header is bound as associated data (AAD) |
| Device authentication | ECDSA P-256 signatures, one private key per device |
| Replay protection | Increasing SEQ + per-session SID + key chain |
| Forward secrecy | Ephemeral Diffie-Hellman + a different key for every message |

The full technical report (diagrams, equations, results) is in [`informe/`](informe/).

---

## Repository contents

```
nodo_p2p/nodo_p2p.ino    Board firmware (the same file for every board)
tools/nodo_pc.py         Simulated node on the PC + key management
tools/atacante.py        Device D: attacks for the security tests
informe/main.tex         Report in IEEE format (ieeetj.cls)
legacy/                  Initial prototype (server, 31-bit DH). History only
```

## Architecture

```
        ┌──────────────── Wi-Fi network, 2.4 GHz (UNTRUSTED) ─────────────┐
        │                                                                  │
        │   Node A            session K_AB            Node B               │
        │   ESP32  ◄───────────────────────────────► ESP32                 │
        │      ▲                                        ▲                  │
        │      │ K_AC                            K_BC   │                  │
        │      └────────────►  Node C  ◄────────────────┘                  │
        │                 (PC, Python, simulated)                          │
        └──────────────────────────────────────────────────────────────────┘
                                   ▲
                       Node D (atacante.py): eavesdrops, modifies,
                       replays, injects, impersonates
```

- **There is no server.** Every node listens on **TCP 8080** and announces its ID by **UDP broadcast on 8081**. The announcement carries no secrets and is not trusted; it only tells a node where to try a connection.
- Every pair of devices has its **own session and its own keys**: what A sends to B cannot be decrypted by C.
- The connection is initiated by the board whose ID sorts first alphabetically. The PC node initiates toward every board it discovers.
- **Node C** exists because there are only two physical boards: it lets the demo show three legitimate devices.

---

## Cryptographic design

All cryptography comes from **mbedTLS** (boards) and Python's **`cryptography`** library (PC). There are no custom algorithms.

| Function | Primitive |
|---|---|
| Session key | Diffie-Hellman, 2048-bit MODP group (RFC 3526 group 14), 256-bit exponent, **new for every session** |
| Authentication | ECDSA P-256 over the full handshake transcript |
| Key derivation | HKDF-SHA256 |
| Encryption | AES-256-GCM (96-bit nonce, 128-bit tag) |
| Key evolution | HKDF chain: a new key for every message |

### Handshake

```
Initiator I                                          Responder R
   │── (1) Hello: ID_I, N_I, Y_I ─────────────────────────►│  is ID_I authorized? if not → close
   │◄── (2) status, ID_R, N_R, Y_R, SIG_R ─────────────────│  signs the transcript T
   │  verifies SIG_R with R's STORED public key            │
   │── (3) SIG_I ──────────────────────────────────────────►│  verifies SIG_I with I's public key
   │◄── (4) result ─────────────────────────────────────────│
   │                                                        │
   │  z = g^(x_I·x_R) mod p ; HKDF(N_I‖N_R, z, "P1-KEYS"‖T)
   │  → CK_I→R , CK_R→I , SID
```

- `T = SHA256(Hello ‖ ID_R ‖ N_R ‖ Y_R)` covers both IDs, both nonces and both DH values. A signature is only valid for **this** handshake and **these** identities.
- Every device stores the **public** keys of the others and verifies with those, never with a key received over the network.
- Stealing one board only allows impersonating **that board**.

### Per-message key chain

```
MK_n     = HKDF(CK_n, "P1-MSG")      key used to encrypt message n
CK_(n+1) = HKDF(CK_n, "P1-CHAIN")    the state advances; CK_n is erased
```

Knowing `MK_n` reveals neither `CK_n` nor any other message key; knowing `CK_n` does not reveal keys of earlier messages. There is **no** post-compromise security: whoever obtains `CK_n` can derive the following keys until the next handshake.

The receiver advances its chain only **after** authenticating a message, so a forged packet cannot desynchronize the session.

### Data packet format

`ID_S ‖ SID ‖ SEQ ‖ N ‖ C ‖ TAG`, integers in little endian.

| Offset | Bytes | Field | Protection |
|---:|---:|---|---|
| 0 | 1 | frame type (`0x01` data, `0x02` ACK) | none |
| 1 | 20 | `ID_S`, sender | AAD |
| 21 | 4 | `SID`, session identifier | AAD |
| 25 | 4 | `SEQ`, sequence number | AAD |
| 29 | 12 | `N`: 8 random bytes ‖ SEQ | AAD and GCM nonce |
| 41 | 2 | `Len`, length of `C` | AAD |
| 43 | n | `C`, ciphertext (n ≤ 1024) | encrypted + tag |
| 43+n | 16 | `TAG` | GCM tag |

Fixed overhead: **58 bytes** per message (42 of header + 16 of tag), plus 1 for the frame type.

---

## Requirements

- 2 × **ESP32 Dev Module** and a **2.4 GHz** Wi-Fi network (the ESP32 cannot see 5 GHz networks). All devices, including the laptop, must be on the same network.
- **Arduino IDE** with the ESP32 core (version 3.3.12 was used).
- **Python 3** and `pip install cryptography` (for `nodo_pc.py` and for the `miembro` mode of `atacante.py`).

---

## Getting started

### 1. Generate the keys (each owner generates ONLY their own)

A private key never leaves its owner's computer; only public keys are exchanged.

```powershell
cd tools

# Bryan: his board and the simulated node on his laptop
python nodo_pc.py --genkey ESP32_Bryan ESP32_Demian

# Christopher, on HIS computer
python nodo_pc.py --genkey ESP32_Christopher
```

Each `--genkey` creates `keys/<ID>.key` (**private**) and adds the public key to `keys/authorized.txt`. It prints the line to share with the others:

```powershell
# Each person runs the PUBLIC line received from the other:
python nodo_pc.py --addpub ESP32_Christopher=04...
python nodo_pc.py --addpub ESP32_Bryan=04...
python nodo_pc.py --addpub ESP32_Demian=04...

# Print the AUTORIZADOS block for the .ino (it must come out IDENTICAL for everyone)
python nodo_pc.py --block
```

Sizes: private key 256 bits (64 hex characters); public key 520 bits (130 hex characters, starts with `04`).

### 2. Configure the firmware

In `nodo_p2p/nodo_p2p.ino`, in the `CONFIGURACIÓN` block:

```cpp
const char* WIFI_SSID   = "YOUR_2.4GHz_NETWORK";
const char* WIFI_PASS   = "YOUR_PASSWORD";
const char* MY_ID       = "ESP32_Bryan";          // different on every board (max. 19 characters)
const char* MY_PRIV_HEX = "...";                  // ONLY the private key of THIS board
const Autorizado AUTORIZADOS[] = { ... };         // block from --block, identical on every board
```

### 3. Upload and check

Open the Serial Monitor at **115200 baud**. On startup every board prints the **fingerprint** of the public key of each authorized device. Both boards must show **the same fingerprints**; if not, their lists differ.

Then the boards discover each other and `==== Clave de sesion establecida con ... ====` appears. The handshake takes on the order of **1 second** (four 2048-bit modular exponentiations plus two ECDSA signatures and their verifications).

### 4. Simulated node on the PC

```powershell
python nodo_pc.py --id ESP32_Demian --ip <your_laptop_WiFi_IP>
```

Useful options: `--peer ESP32_Bryan=192.168.1.32` (fixes an IP by hand if discovery fails), `--keydir` (key folder) and `--quiet`.

### Serial Monitor commands (and `nodo_pc.py` commands)

| Input | Action |
|---|---|
| `text` | encrypts and sends to every connected board |
| `@ID text` | sends to one board only |
| `1` | normal test message |
| `2` | test: flips 1 byte of the ciphertext |
| `3` | test: flips 1 byte of the tag |
| `4` | test: retransmits the last accepted packet (replay) |
| `5` | test: falsifies the sender (`ID_S`) |
| `6` | test: packet encrypted with a key that is not the session key |
| `p` | board status |
| `k` | key chain state |
| `m` | menu |

With `VERBOSE = true` (the default) every node prints `g` and `p`, the DH keys, the shared secret, the session keys and, for each message: plaintext, ciphertext, tag, message key and recovered plaintext. Long lines are printed in 64-character blocks.

---

## Security tests

From the laptop, on the same network, against the IP of one board:

```powershell
python atacante.py <board_IP> no-autorizado
python atacante.py <board_IP> suplantar ESP32_Christopher
python atacante.py <board_IP> miembro ESP32_Christopher ESP32_Demian
python atacante.py <board_IP> inyectar
```

| # | Scenario | How it is tested | Rejected by |
|---|---|---|---|
| T1 | Normal exchange | `1` or free text | — (accepted) |
| T2 | Altered ciphertext | `2` | GCM tag |
| T3 | Altered tag | `3` | GCM tag |
| T4 | Replay of an accepted packet | `4` right after an accepted message | SEQ and key chain |
| T5 | Falsified sender | `5` | ID check and AAD |
| T6 | Packet with a false key | `6` | GCM tag |
| T7 | Device not in the allowlist | `atacante.py ... no-autorizado` | allowlist |
| T8 | Valid ID without its private key | `atacante.py ... suplantar <ID>` | signature `SIG_I` |
| T9 | Data without a handshake | `atacante.py ... inyectar` | handshake parser |
| T10 | Valid key of one device used to pose as another | `atacante.py ... miembro <claimed_ID> <key_owner_ID>` | signature against the stored public key |

In `miembro`, the first ID is **who the attacker pretends to be** and the second is **whose private key it uses** (it reads `keys/<ID>.key`).

In T7 to T10 the board prints an `[ALERTA]` line with the attempt and closes the connection. In T2 to T6 the sender sees `RECHAZADO` in the ACK and the receiver prints the technical reason.

**Recommended order for a demonstration:**

1. Normal messages, and `k` to show how the key changes with each one.
2. `4` right after an accepted message.
3. `6`, which does not break the session.
4. The four modes of `atacante.py`.
5. **Restart the boards before trying `2`, `3` or `5`**: these tests alter the packet after the sender has already advanced its chain, so the two chains end up different and the session must be re-established. This is an effect of testing from the sender's side, not of an external attack.

---

## Results

Measured on two ESP32 boards with the final firmware (`VERBOSE` on):

| Metric | Result |
|---|---|
| AES-GCM encryption, 36 B | ≈ 202 µs (n = 13) |
| AES-GCM encryption, 173 B | 272 µs (n = 1) |
| Decryption + verification (accepted) | ≈ 200 µs (n = 3) |
| Packet dropped by replay or ID check | 5 to 8 µs |
| Overhead per message | 58 B fixed |
| Handshake (initiator) | typical ≈ 1.2 s; also 3.4 s and 15.0 s in two runs |
| ACK round trip (accepted) | median 65 ms (46 to 677 ms, n = 11) |

Encryption is ≈ 0.3 % of the round trip: latency is dominated by the network. The round trip includes the receiver's console output and was not isolated. Samples are few, so these are orders of magnitude, not precise averages. The handshake of an earlier HMAC-based revision took 189 ms; the difference is attributed to the software ECDSA signatures.

---

## Limitations

- **Manual distribution of public keys** and no revocation: adding or removing a device requires reprogramming every board.
- Each private key is compiled into the firmware and flash encryption is not enabled: stealing a board reveals its key (and allows impersonating only that board).
- **No post-compromise security**: see the key chain.
- The chain is strictly sequential: a lost or reordered authentic packet desynchronizes the session and requires a new handshake. TCP delivers in order, so this is rare.
- ACKs, the frame-type byte and the discovery announcements are not authenticated. Forging them can disturb a connection, but cannot make a receiver accept a message.
- A responder computes a DH pair and a signature before the initiator proves its identity, and IDs are public: a flood of `Hello` messages could exhaust a board. There is no rate limiting.
- Message lengths and who talks to whom are visible.
- There is no formal verification or side-channel analysis.

---

## Repository safety

**Do not push to GitHub** (the repository is public):

- `keys/` and any `*.key` file: they contain **private** keys.
- A `.ino` with `MY_PRIV_HEX` or the Wi-Fi password filled in. Push only the placeholder version.

Add this to `.gitignore`:

```
keys/
*.key
```

The `AUTORIZADOS` block (public keys) is public.

---

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| The board only prints dots | 5 GHz network or a misspelled `WIFI_SSID`. Use a 2.4 GHz network. |
| `MY_PRIV_HEX no es una clave privada valida` | The private key was not pasted, or it is not 64 hex characters. |
| `MY_PRIV_HEX no corresponde a la clave publica de este MY_ID` | `MY_ID` is not the one of that key, or the `AUTORIZADOS` list is not the one `--genkey` produced. |
| Fingerprints differ between boards | Different `AUTORIZADOS` lists. Run `--block` again and paste the same block on every board. |
| Boards discover each other but no session opens | The router isolates clients from each other. Try a phone hotspot on 2.4 GHz. |
| The PC node does not find the boards | Laptop and boards on different subnets (for example, the laptop on 5 GHz). Check `ipconfig` or use `--peer`. |
| `RECHAZADO` on everything after a `2`, `3` or `5` test | Expected: the chains are desynchronized. Restart the boards. |
| `nodo_pc.py --genkey` says the key already exists | A safeguard against overwriting your keys. Use `--force` only if you are going to reprogram every board. |

---

## References

- RFC 3526: MODP Diffie-Hellman groups · RFC 5869: HKDF
- NIST FIPS 186-4: ECDSA · NIST SP 800-38D: AES-GCM
- The Double Ratchet Algorithm (Marlinspike and Perrin, Signal)
- [mbedTLS](https://github.com/Mbed-TLS/mbedtls) · [`cryptography`](https://cryptography.io)
