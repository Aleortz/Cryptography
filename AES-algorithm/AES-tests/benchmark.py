import os
import time
import sys

sys.path.append('C:\\Users\\alejo\\SEMESTER_2_2026\\Cryptography\\AES-algorithm\\AES-implementation')

from AES_implementation import cipher, decipher

def procesar_bloques(datos_bytes, key_lista, modo="cifrar"):
    """
    Procesa un bloque de datos masivo dividiéndolo en fragmentos de 16 bytes.
    Simula el comportamiento del núcleo criptográfico sin aplicar un modo de operación complejo.
    """
    resultado = bytearray()
    
    # Avanza de 16 en 16 bytes
    for i in range(0, len(datos_bytes), 16):
        bloque = list(datos_bytes[i:i+16])
        
        # Padding simple con ceros si el último bloque no es múltiplo de 16
        if len(bloque) < 16:
            bloque += [0] * (16 - len(bloque))
            
        if modo == "cifrar":
            bloque_procesado = cipher(bloque, key_lista)
        else:
            bloque_procesado = decipher(bloque, key_lista)
            
        resultado.extend(bloque_procesado)
        
    return resultado

def ejecutar_benchmark():
    # Tamaños exigidos en el laboratorio (en bytes)
    tamanos = {
        "1 MB": 1 * 1024 * 1024,
        "10 MB": 10 * 1024 * 1024,
        "100 MB": 100 * 1024 * 1024
    }
    
    claves = {
        #"AES-128": list(os.urandom(16)),
        #"AES-192": list(os.urandom(24)),
        "AES-256": list(os.urandom(32))
    }
    
    iteraciones = 3
    
    print(f"{'Algoritmo':<10} | {'Datos':<8} | {'Operación':<10} | {'Tiempo Medio (s)':<18} | {'Throughput (MB/s)':<18}")
    print("-" * 75)
    
    for nombre_aes, key in claves.items():
        for nombre_tamano, tamano_bytes in tamanos.items():
            datos_prueba = os.urandom(tamano_bytes)
            tamano_mb = tamano_bytes / (1024 * 1024)
            
            # --- Benchmark de Cifrado ---
            tiempos_cifrado = []
            for _ in range(iteraciones):
                inicio = time.time()
                datos_cifrados = procesar_bloques(datos_prueba, key, modo="cifrar")
                tiempos_cifrado.append(time.time() - inicio)
            
            # Cálculo de promedios e implementación de R = D / T
            tiempo_medio_c = sum(tiempos_cifrado) / iteraciones
            throughput_c = tamano_mb / tiempo_medio_c
            
            print(f"{nombre_aes:<10} | {nombre_tamano:<8} | {'Cifrado':<10} | {tiempo_medio_c:<18.4f} | {throughput_c:<18.4f}")
            
            # --- Benchmark de Descifrado ---
            tiempos_descifrado = []
            for _ in range(iteraciones):
                inicio = time.time()
                _ = procesar_bloques(datos_cifrados, key, modo="descifrar")
                tiempos_descifrado.append(time.time() - inicio)
            
            tiempo_medio_d = sum(tiempos_descifrado) / iteraciones
            throughput_d = tamano_mb / tiempo_medio_d
            
            print(f"{nombre_aes:<10} | {nombre_tamano:<8} | {'Descifrado':<10} | {tiempo_medio_d:<18.4f} | {throughput_d:<18.4f}")
            print("-" * 75)

if __name__ == "__main__":
    ejecutar_benchmark()