#include <iostream>
#include <thread>
#include <vector>
#include <cstdio>

void loop_break(int x, char *buffer) {
	for (int i = 0; i < x; ++i) {
		if (buffer[i] == '1')
			break;
		if (buffer[i] == '2')
			break;
		printf("%d\n", buffer[i]);
	}
}

// Function that will be called by each thread
void thread_function(const char* filename) {
    // Open the file using fopen
    FILE* file = fopen(filename, "rb");

    if (!file) {
        std::cerr << "Failed to open the file: " << filename << std::endl;
        return;
    }

    // Read the first byte from the file using fread
    char first_byte;
    size_t bytes_read = fread(&first_byte, 1, 1, file);

    char buffer[20] = {0};
    fread(buffer, sizeof(char), 10, file);
	loop_break(5,buffer);

    if (bytes_read == 1) {
        std::cout << "First byte of " << filename << ": " << int(first_byte) << std::endl;
    } else {
        std::cerr << "Failed to read the first byte from " << filename << std::endl;
    }

    // Close the file using fclose
    fclose(file);
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
            const char* filename = argv[1];
            threads.emplace_back(thread_function, filename);
    }

    // Wait for all threads to finish
    for (std::thread& thread : threads) {
        thread.join();
    }

    FILE* file = fopen(argv[1], "rb");

    if (!file) {
        std::cerr << "Failed to open the file: " << argv[1] << std::endl;
        return -1;
    }

    char buffer[20] = {0};
    fread(buffer, sizeof(char), 10, file);
	loop_break(5, buffer);

    std::cout << "Main thread: All threads finished" << std::endl;

    return 0;
}
