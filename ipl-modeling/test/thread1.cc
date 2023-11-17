#include <iostream>
#include <thread>
#include <fstream>
#include <vector>

// Function that will be called by each thread
void thread_function(const std::string& filename) {
    // Open the file
    std::ifstream file(filename, std::ios::binary);

    if (!file) {
        std::cerr << "Failed to open the file: " << filename << std::endl;
        return;
    }

    // Read the first byte from the file
    char first_byte;
    if (file.read(&first_byte, 1)) {
        std::cout << "First byte of " << filename << ": " << int(first_byte) << std::endl;
    } else {
        std::cerr << "Failed to read the first byte from " << filename << std::endl;
    }

    // Close the file
    file.close();
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <filename1> <filename2> ... <filename10>" << std::endl;
        return 1;
    }

    // Create a vector of threads
    std::vector<std::thread> threads;

    // Start 10 threads, one for each file
    for (int i = 1; i <= 10; i++) {
        const std::string filename = argv[1];
        threads.emplace_back(thread_function, filename);
    }

    // Wait for all threads to finish
    for (std::thread& thread : threads) {
        thread.join();
    }

    std::cout << "Main thread: All threads finished" << std::endl;

    return 0;
}
