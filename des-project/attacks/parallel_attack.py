import time
import sys
import multiprocessing

sys.path.append('C:\\Users\\alejo\\SEMESTER_2_2026\\Cryptography\\des-project\\deslib')

from api import des_encrypt_block
from keyspace import int_to_des_key
from brute_force import brute_force_des

def worker_task(worker_id: int, plaintext: bytes, ciphertext: bytes, start: int, end: int, stop_event: multiprocessing.Event, result_queue: multiprocessing.Queue)-> None:
    """Function that will be executed by each CPU core independently."""
    keys_tested = 0
    
    for candidate_int in range(start, end):
        # Detect if another worker has already found the key
        if stop_event.is_set():
            break
            
        keys_tested += 1
        candidate_key = int_to_des_key(candidate_int)
        encrypted = des_encrypt_block(candidate_key, plaintext)
        
        if encrypted == ciphertext:
            # If found, signal other workers to stop and report the result
            stop_event.set()
            result_queue.put((worker_id, candidate_key, keys_tested))
            return
            
    # if the loop completes without finding the key, report the number of keys tested
    result_queue.put((worker_id, None, keys_tested))