import matplotlib.pyplot as plt
import os

def generate_performance_plots():
    """
    Generates and saves the performance plots required for the Lab 2 report.
    Data is based on the 20-bit key space brute-force parallel execution.
    """
    # Experimental data from the 20-bit key space benchmark
    workers = [1, 2, 4]
    keys_per_second = [2864.85, 760.44, 1338.55]
    speedup = [1.00, 898.04, 655.05]

    # Ensure the results directory exists to store the images
    os.makedirs("results", exist_ok=True)

    # ---------------------------------------------------------
    # 1. Plot: Workers vs. Keys/s (Throughput)
    # ---------------------------------------------------------
    plt.figure(figsize=(8, 5))
    plt.plot(workers, keys_per_second, marker='o', linestyle='-', color='b', linewidth=2, markersize=8)
    
    plt.title("Workers vs. Throughput (Keys/s)", fontsize=14, fontweight='bold')
    plt.xlabel("Number of Workers (p)", fontsize=12)
    plt.ylabel("Throughput (Keys/s)", fontsize=12)
    plt.xticks(workers)
    plt.grid(True, linestyle='--', alpha=0.7)
    
    # Save the plot
    throughput_path = "results/workers_vs_keys_per_sec.png"
    plt.savefig(throughput_path, bbox_inches='tight')
    print(f"[SUCCESS] Plot saved: {throughput_path}")
    plt.close()

    # ---------------------------------------------------------
    # 2. Plot: Workers vs. Speedup
    # ---------------------------------------------------------
    plt.figure(figsize=(8, 5))
    
    # Actual experimental speedup
    plt.plot(workers, speedup, marker='s', linestyle='-', color='r', linewidth=2, markersize=8, label='Experimental Speedup')
    
    # Theoretical linear speedup for comparison
    plt.plot(workers, workers, marker='', linestyle='--', color='g', label='Theoretical Linear Speedup')
    
    plt.title("Workers vs. Speedup", fontsize=14, fontweight='bold')
    plt.xlabel("Number of Workers (p)", fontsize=12)
    plt.ylabel("Speedup Factor", fontsize=12)
    plt.xticks(workers)
    plt.legend()
    plt.grid(True, linestyle='--', alpha=0.7)
    
    # Save the plot
    speedup_path = "results/workers_vs_speedup.png"
    plt.savefig(speedup_path, bbox_inches='tight')
    print(f"[SUCCESS] Plot saved: {speedup_path}")
    plt.close()

if __name__ == "__main__":
    print("Generating benchmark plots...")
    generate_performance_plots()
    print("All plots generated successfully!")