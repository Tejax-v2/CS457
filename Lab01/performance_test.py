import os
import time
import psutil
import matplotlib.pyplot as plt
from aes256 import encrypt_file, decrypt_file

# Define a function to measure encryption and decryption performance
def measure_performance(password: str, input_sizes: list):
    results = []
    for size in input_sizes:
        # Generate random plaintext of the given size
        plaintext = os.urandom(size)

        # Measure encryption speed
        start_time = time.time()
        ciphertext = encrypt_file(plaintext, password, isFile = False)
        enc_time = time.time() - start_time

        # Measure decryption speed
        start_time = time.time()
        decrypted_text = decrypt_file(ciphertext, password, isFile = False)
        dec_time = time.time() - start_time

        # Memory usage and CPU utilization
        process = psutil.Process()
        memory_usage = process.memory_info().rss / 1024 / 1024  # Convert to MB
        cpu_utilization = process.cpu_percent(interval=0.1)

        results.append({
            "input_size": size,
            "enc_time": enc_time,
            "dec_time": dec_time,
            "memory_usage": memory_usage,
            "cpu_utilization": cpu_utilization
        })

    return results

# Visualize the results
def plot_results(results):
    sizes = [r["input_size"] for r in results]
    enc_times = [r["enc_time"] for r in results]
    dec_times = [r["dec_time"] for r in results]
    memory_usages = [r["memory_usage"] for r in results]
    cpu_utilizations = [r["cpu_utilization"] for r in results]

    plt.figure(figsize=(12, 8))

    # Plot encryption and decryption times
    plt.subplot(3, 1, 1)
    plt.plot(sizes, enc_times, label="Encryption Time", marker="o")
    plt.plot(sizes, dec_times, label="Decryption Time", marker="o")
    plt.xlabel("Input Size (bytes)")
    plt.ylabel("Time (seconds)")
    plt.title("Encryption/Decryption Times")
    plt.legend()
    plt.grid()

    # Plot memory usage
    plt.subplot(3, 1, 2)
    plt.plot(sizes, memory_usages, label="Memory Usage (MB)", color="orange", marker="o")
    plt.xlabel("Input Size (bytes)")
    plt.ylabel("Memory Usage (MB)")
    plt.title("Memory Usage")
    plt.grid()

    # Plot CPU utilization
    plt.subplot(3, 1, 3)
    plt.plot(sizes, cpu_utilizations, label="CPU Utilization (%)", color="green", marker="o")
    plt.xlabel("Input Size (bytes)")
    plt.ylabel("CPU Utilization (%)")
    plt.title("CPU Utilization")
    plt.grid()

    plt.tight_layout()
    plt.show()

# Provide optimization recommendations
def provide_recommendations(results):
    avg_enc_time = sum(r["enc_time"] for r in results) / len(results)
    avg_dec_time = sum(r["dec_time"] for r in results) / len(results)
    avg_memory = sum(r["memory_usage"] for r in results) / len(results)
    avg_cpu = sum(r["cpu_utilization"] for r in results) / len(results)

    print("Optimization Recommendations:")
    print(f"- Average Encryption Time: {avg_enc_time:.6f} seconds")
    print(f"- Average Decryption Time: {avg_dec_time:.6f} seconds")
    print(f"- Average Memory Usage: {avg_memory:.2f} MB")
    print(f"- Average CPU Utilization: {avg_cpu:.2f}%")

    if avg_cpu > 80:
        print("- Consider using hardware acceleration for AES (e.g., AES-NI).")
    if avg_memory > 100:
        print("- Optimize memory usage by processing data in smaller chunks.")
    if avg_enc_time + avg_dec_time > 0.1:
        print("- Experiment with alternative modes like AES-GCM for combined encryption and integrity verification.")

# Main function
if __name__ == "__main__":
    password = input("Enter password for performance testing: ")
    input_sizes = [1024, 4096, 16384, 65536, 262144, 1048576]  # 1KB to 1MB

    print("Running performance tests...")
    results = measure_performance(password, input_sizes)
    
    print("Plotting results...")
    plot_results(results)

    print("Providing recommendations...")
    provide_recommendations(results)
