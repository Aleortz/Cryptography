import matplotlib.pyplot as plt

# Data extracted from the execution (Search space 2^20)
workers = [1, 2, 4, 6]
keys_per_second = [3276.81, 5932.15, 12629.07, 16650.57]
speedup = [1.0000, 1.8103, 3.8541, 5.0813]

# ---------------------------------------------------------
# Plot 1: Workers vs. Keys/s
# ---------------------------------------------------------
plt.figure(figsize=(8, 5))
plt.plot(workers, keys_per_second, marker='o', linestyle='-', color='b', linewidth=2, markersize=8)
plt.title('Workers vs. Throughput (Keys/s)', fontsize=14)
plt.xlabel('Number of CPU Workers', fontsize=12)
plt.ylabel('Keys Tested per Second', fontsize=12)
plt.grid(True, linestyle='--', alpha=0.7)
plt.xticks(workers)

# Save the image in the current directory
img1_name = 'workers_vs_keys.png'
plt.savefig(img1_name, bbox_inches='tight')
print(f"Plot saved: {img1_name}")
plt.clf() # Clear figure

# ---------------------------------------------------------
# Plot 2: Workers vs. Speedup (Sp)
# ---------------------------------------------------------
plt.figure(figsize=(8, 5))

# Actual measured experiment line
plt.plot(workers, speedup, marker='s', linestyle='-', color='r', linewidth=2, markersize=8, label='Measured Speedup')

# Theoretical ideal line (where X workers = X speedup)
ideal_speedup = workers
plt.plot(workers, ideal_speedup, linestyle='--', color='g', alpha=0.7, label='Ideal Linear Speedup ($S_p = W$)')

plt.title('Workers vs. Speedup ($S_p$)', fontsize=14)
plt.xlabel('Number of CPU Workers', fontsize=12)
plt.ylabel('Speedup ($S_p$)', fontsize=12)
plt.grid(True, linestyle='--', alpha=0.7)
plt.xticks(workers)
plt.legend(loc='upper left')

# Save the image in the current directory
img2_name = 'workers_vs_speedup.png'
plt.savefig(img2_name, bbox_inches='tight')
print(f"Plot saved: {img2_name}")