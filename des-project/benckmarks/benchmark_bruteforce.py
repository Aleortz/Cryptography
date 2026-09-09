import time
import sys
import os
import multiprocessing

# Ajusta esta ruta a la de tu proyecto
sys.path.append('C:\\Users\\alejo\\SEMESTER_2_2026\\Cryptography\\des-project\\deslib')
sys.path.append('C:\\Users\\alejo\\SEMESTER_2_2026\\Cryptography\\des-project\\attacks')


from api import des_encrypt_block
from keyspace import int_to_des_key
from brute_force import brute_force_des
from parallel_attack import worker_task

# Test Configuration
PLAINTEXT = b'ABCDEFGH'
CIPHERTEXT = bytes.fromhex('56467e175662aff6') #ciphertext in hexagesimal representationn
SEARCH_SPACE = 2**20 # Adjust the search space for the benchmark (e.g., 2^18)

ITERATIONS = 3
AVAILABLE_CORES = 6

def run_sequential():
    start_time = time.time()
    # Use brute_force_des from brute_force.py
    key, tested = brute_force_des(PLAINTEXT, CIPHERTEXT, 0, SEARCH_SPACE)
    execution_time = time.time() - start_time
    return execution_time, tested

def run_parallel(p):
    stop_event = multiprocessing.Event()
    result_queue = multiprocessing.Queue()
    processes = []
    
    interval = SEARCH_SPACE // p
    
    start_time = time.time()
    
    for i in range(p):
        start_idx = i * interval
        end_idx = SEARCH_SPACE if i == p - 1 else (i + 1) * interval
        
        # Use worker_task from parallel_attack.py 
        proc = multiprocessing.Process(
            target=worker_task, 
            args=(i, PLAINTEXT, CIPHERTEXT, start_idx, end_idx, stop_event, result_queue)
        )
        processes.append(proc)
        proc.start()
        
    for proc in processes:
        proc.join()
        
    execution_time = time.time() - start_time
    
    total_tested = 0
    while not result_queue.empty():
        _, _, tested = result_queue.get()
        total_tested += tested
        
    return execution_time, total_tested

def format_time(seconds):
    hours = seconds / 3600
    days = hours / 24
    years = days / 365.25
    return f"{seconds:.2e} s | {hours:.2e} h | {days:.2e} d | {years:.2e} y"

if __name__ == '__main__':
    print("Starting DES Benchmark (Exercises 8-11)")
    print(f"Iterations per test: {ITERATIONS}")
    print(f"Available cores: {AVAILABLE_CORES}\n")
    
    results = {}
    workers_list = [1, 2, 4, AVAILABLE_CORES]
    
    # Execute tests
    for p in workers_list:
        print(f"Running with {p} worker(s)...")
        times = []
        tests = []
        if p == 1:
            for i in range(ITERATIONS):
                t, n = run_sequential()
                times.append(t)
                tests.append(n)
            avg_time = sum(times[0:ITERATIONS]) / ITERATIONS
            avg_tested = sum(tests[0:ITERATIONS]) / ITERATIONS
            throughput = avg_tested / avg_time
            results[p] = {
            'time': avg_time,
            'tested': avg_tested,
            'throughput': throughput
            }
                    #For Excercise 8, calculate average time and tested keys for 1 worker and throughput (keys/s)
            print("\n--- Exercise 8: Sequential Execution (1 worker) ---")
            print(f"{'Attempt':<10} | {'Time [s]':<10} | {'Keys Tested':<15} | {'Throughput [keys/s]':<20}")
            print("-" * 65)
            
            # Imprimir las 3 iteraciones individuales
            for i in range(3):
                t = times[i]
                n = tests[i]
                r = n / t if t > 0 else 0  # Prevenir división por cero por seguridad
                print(f"{i+1:<10} | {t:<10.4f} | {n:<15.0f} | {r:<20.2f}")
                
            print("-" * 65)
            
            # Imprimir el promedio general guardado en results[1]
            avg_time = results[1]['time']
            avg_tested = results[1]['tested']
            avg_throughput = results[1]['throughput']
            
            print(f"{'Average':<10} | {avg_time:<10.4f} | {avg_tested:<15.0f} | {avg_throughput:<20.2f}\n")
        else:
            t, n = run_parallel(p)
            times.append(t)
            tests.append(n)

            results[p] = {
            'time': t,
            'tested': n,
            'throughput': n / t
            }

    
    # Exercise 10: Parallel Performance (Table)
    print("\n--- Performance Table (Exercise 10) ---")
    print(f"{'Workers':<10} | {'Time [s]':<10} | {'Keys Tested':<15} | {'Keys/s':<15} | {'Speedup (Sp)':<15} | {'Efficiency (Ep)':<15}")
    print("-" * 85)
    
    t1 = results[1]['time']
    best_throughput = 0
    
    for p in workers_list:
        res = results[p]
        sp = t1 / res['time']
        ep = sp / p
        
        if res['throughput'] > best_throughput:
            best_throughput = res['throughput']
            
        print(f"{p:<10} | {res['time']:<10.4f} | {res['tested']:<15.0f} | {res['throughput']:<15.2f} | {sp:<15.4f} | {ep:<15.4f}")

    # Exercise 11: Extrapolation to Full DES
    print("\n--- Extrapolation to Full DES (Exercise 11) ---")
    t_max = (2**56) / best_throughput
    t_avg = (2**55) / best_throughput
    
    print(f"Best measured throughput (R): {best_throughput:.2f} keys/s")
    print(f"T_max (Full 2^56 search): {format_time(t_max)}")
    print(f"T_avg (Average 2^55 recovery): {format_time(t_avg)}")