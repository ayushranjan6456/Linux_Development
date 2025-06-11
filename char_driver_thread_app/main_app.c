#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>          // For open(), O_RDWR
#include <unistd.h>         // For close(), read(), write()
#include <sys/ioctl.h>      // For ioctl()
#include <errno.h>          // For errno
#include <pthread.h>        // For pthreads, mutexes, condition variables
#include <stdbool.h>        // For bool type
#include <signal.h>         // For signal handling (SIGINT, SIGTERM, SIGUSR1)
#include <string.h>         // For strerror

// Include the shared ioctl header (ensure this file is in the same directory or properly linked)
#include "my_device_ioctl.h" // Assuming it's in the same directory or properly linked

#define DEVICE_PATH "/dev/my_device_node"
#define KERNEL_READ_BUF_SIZE 64 // Size of chunks to read from kernel
#define USER_BUFFER_CAPACITY 10 // Number of data blocks in user-space queue
#define DATA_BLOCK_SIZE KERNEL_READ_BUF_SIZE // Size of each block in user-space queue

// --- User-space Circular Buffer Structure ---
typedef struct {
    char data[DATA_BLOCK_SIZE]; // Data payload
    size_t len;                 // Length of actual data in payload
} data_block_t;

data_block_t user_circular_buffer[USER_BUFFER_CAPACITY];
int user_head = 0; // Write pointer for user-space buffer
int user_tail = 0; // Read pointer for user-space buffer
int user_count = 0; // Current number of blocks in user-space buffer

// --- Synchronization Primitives ---
pthread_mutex_t user_buffer_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t data_available_cond = PTHREAD_COND_INITIALIZER;
pthread_cond_t space_available_cond = PTHREAD_COND_INITIALIZER;

// --- Control Flag for Threads ---
volatile bool app_running = true;
static int global_dev_fd = -1; // Global device file descriptor
pthread_t producer_tid_global; // To store producer's TID for signaling

// --- Producer Thread Function (Reads from Kernel, Writes to User Buffer) ---
void* data_producer_thread(void* arg) {
    int dev_fd = *(int*)arg; // Get the device file descriptor
    char kernel_read_buf[KERNEL_READ_BUF_SIZE];
    ssize_t bytes_read;

    // --- NEW: Unblock SIGUSR1 specifically for this thread ---
    sigset_t oldset; // To store previous mask
    sigset_t newset;
    sigemptyset(&newset);
    sigaddset(&newset, SIGUSR1); // Add SIGUSR1 to the set
    // Unblock SIGUSR1 in this thread, saving previous mask
    pthread_sigmask(SIG_UNBLOCK, &newset, &oldset);

    printf("[Producer]: Thread started. Reading from %s\n", DEVICE_PATH);

    while (app_running) { // Keep checking app_running at the start of the loop
        // It's good practice to ensure app_running is false before a blocking call.
        // If it somehow turned false after the last loop iteration check, this catches it.
        if (!app_running) {
            printf("[Producer]: App stopping (pre-read check). Exiting...\n");
            break; // Exit the loop
        }

        memset(kernel_read_buf, 0, KERNEL_READ_BUF_SIZE);
        bytes_read = read(dev_fd, kernel_read_buf, KERNEL_READ_BUF_SIZE);

        // --- CRITICAL ADDITION: Check app_running IMMEDIATELY after read returns ---
        // This ensures that if app_running changed while read() was blocking,
        // we react before re-entering the loop or doing more work.
        if (!app_running) {
            printf("[Producer]: App stopping (post-read check). Exiting...\n");
            break; // Exit the while loop immediately
        }

        if (bytes_read < 0) {
            // Corrected: Only check for EINTR in user-space for signal interruptions
            if (errno == EINTR) {
                printf("[Producer]: Read interrupted by signal (errno %d: %s). Exiting gracefully.\n", errno, strerror(errno));
                // --- MOST IMPORTANT CHANGE: Direct exit for EINTR ---
                goto producer_exit; // Jump to cleanup and exit point
            }
            if (errno == EBADF || errno == EINVAL) { // File descriptor invalid/closed
                printf("[Producer]: Device FD closed (errno %d: %s). Exiting definitively.\n", errno, strerror(errno));
                goto producer_exit; // Jump to cleanup and exit point
            }
            // For any other unexpected read error
            perror("[Producer]: Failed to read from device (unexpected error)");
            app_running = false; // Indicate critical error, terminate app
            goto producer_exit; // Jump to cleanup and exit point
        } else if (bytes_read == 0) {
            // Kernel buffer currently empty and no data, or EOF.
            // For a character device, 0 bytes means no data currently available.
            // With blocking read, it implies it would block again.
            printf("[Producer]: Kernel buffer currently empty (0 bytes read). Waiting...\n");
            usleep(10000); // Sleep for 10ms to avoid busy-wait if read() returns 0 repeatedly
            continue; // Continue to the next loop iteration to re-evaluate `while(app_running)`
        }

        // --- Only proceed to process data if bytes_read was positive ---
        if (bytes_read > 0) {
            // 2. Add data to user-space circular buffer
            pthread_mutex_lock(&user_buffer_mutex); // Acquire lock

            // Wait if user-space buffer is full
            while (user_count == USER_BUFFER_CAPACITY && app_running) {
                printf("[Producer]: User buffer full. Waiting for space...\n");
                pthread_cond_wait(&space_available_cond, &user_buffer_mutex);
            }

            if (!app_running) { // Check if app_running became false while waiting on condition
                pthread_mutex_unlock(&user_buffer_mutex);
                break; // Exit if app_running changed during wait
            }

            // Copy data to user-space buffer
            strncpy(user_circular_buffer[user_head].data, kernel_read_buf, bytes_read);
            user_circular_buffer[user_head].data[bytes_read] = '\0'; // Null-terminate
            user_circular_buffer[user_head].len = bytes_read;

            user_head = (user_head + 1) % USER_BUFFER_CAPACITY;
            user_count++;

            printf("[Producer]: Added '%s' (%zd bytes) to user buffer. Count: %d\n",
                   user_circular_buffer[user_head == 0 ? USER_BUFFER_CAPACITY - 1 : user_head - 1].data,
                   bytes_read, user_count);

            pthread_cond_signal(&data_available_cond); // Signal consumer that data is available
            pthread_mutex_unlock(&user_buffer_mutex); // Release lock
        }
    } // end while loop

producer_exit: // Label for goto statement
    // --- Restore original signal mask (good practice) ---
    pthread_sigmask(SIG_SETMASK, &oldset, NULL);

    printf("[Producer]: Thread exiting.\n");
    return NULL; // Explicitly return NULL to exit the thread
}

// --- Consumer Thread Function (Reads from User Buffer, Processes Data) ---
void* data_consumer_thread(void* arg) {
    (void)arg; // Cast to void to suppress unused argument warning
    data_block_t processed_block;

    // --- NEW: Unblock SIGUSR1 specifically for this thread (though not strictly needed for consumer) ---
    sigset_t oldset; // To store previous mask
    sigset_t newset;
    sigemptyset(&newset);
    sigaddset(&newset, SIGUSR1); // Add SIGUSR1 to the set
    // Unblock SIGUSR1 in this thread, saving previous mask
    pthread_sigmask(SIG_UNBLOCK, &newset, &oldset);

    printf("[Consumer]: Thread started. Processing data.\n");

    while (app_running) {
        pthread_mutex_lock(&user_buffer_mutex); // Acquire lock

        // Wait if user-space buffer is empty
        while (user_count == 0 && app_running) {
            printf("[Consumer]: User buffer empty. Waiting for data...\n");
            pthread_cond_wait(&data_available_cond, &user_buffer_mutex);
        }

        if (!app_running) { // Check if app_running became false while waiting
            pthread_mutex_unlock(&user_buffer_mutex);
            break;
        }

        // Copy data from user-space buffer (simulate processing)
        memcpy(processed_block.data, user_circular_buffer[user_tail].data, user_circular_buffer[user_tail].len);
        processed_block.data[user_circular_buffer[user_tail].len] = '\0'; // Null-terminate
        processed_block.len = user_circular_buffer[user_tail].len;

        user_tail = (user_tail + 1) % USER_BUFFER_CAPACITY;
        user_count--;

        printf("[Consumer]: Processed '%s' (%zu bytes). Remaining in user buffer: %d\n",
               processed_block.data, processed_block.len, user_count);

        pthread_cond_signal(&space_available_cond); // Signal producer that space is available
        pthread_mutex_unlock(&user_buffer_mutex); // Release lock

        // Simulate work being done by consumer
        usleep(50000); // Process for 50ms (adjust to observe buffering)
    }

    // --- NEW: Restore original signal mask (good practice) ---
    pthread_sigmask(SIG_SETMASK, &oldset, NULL);

    printf("[Consumer]: Thread exiting.\n");
    return NULL;
}

// --- Signal Handler for graceful shutdown ---
void sig_handler(int signo) {
    if (signo == SIGINT || signo == SIGTERM) {
        printf("\n[Main]: Signal %d received. Setting app_running to false.\n", signo);
        app_running = false;
        // Broadcast to wake up any threads waiting on conditions
        pthread_cond_broadcast(&data_available_cond);
        pthread_cond_broadcast(&space_available_cond);
        // Important: Do NOT call pthread_kill here in the SIGINT/SIGTERM handler.
        // pthread_kill is not async-signal-safe.
    } else if (signo == SIGUSR1) {
        // This handler for SIGUSR1 is mainly to catch it and allow read() to return EINTR.
        // We don't need to do anything specific here, just acknowledging its receipt.
        printf("[Producer]: Caught SIGUSR1. Read should return EINTR.\n");
    }
}

// --- Main Application ---
int main() {
    pthread_t consumer_tid; // Producer TID is now global: producer_tid_global

    printf("--- User-Space Application (Producer-Consumer) ---\n");

    // --- NEW: Block SIGUSR1 in main thread to prevent it from being caught here ---
    sigset_t set, oldset; // 'set' for signals to block, 'oldset' to save original mask
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    // Block SIGUSR1 for the main thread and for newly created threads by default
    pthread_sigmask(SIG_BLOCK, &set, &oldset);


    // 1. Open the device (blocking mode by default)
    global_dev_fd = open(DEVICE_PATH, O_RDWR);
    if (global_dev_fd < 0) {
        perror("Failed to open device");
        // --- NEW: Restore signal mask before exit ---
        pthread_sigmask(SIG_SETMASK, &oldset, NULL);
        return 1;
    }
    printf("[Main]: Successfully opened device %s (fd: %d)\n", DEVICE_PATH, global_dev_fd);

    // 2. Set up signal handler for graceful exit (for SIGINT/SIGTERM and SIGUSR1)
    if (signal(SIGINT, sig_handler) == SIG_ERR ||
        signal(SIGTERM, sig_handler) == SIG_ERR ||
        signal(SIGUSR1, sig_handler) == SIG_ERR) { // NEW: Register handler for SIGUSR1
        perror("[Main]: Can't catch signals");
        close(global_dev_fd);
        global_dev_fd = -1;
        // --- NEW: Restore signal mask before exit ---
        pthread_sigmask(SIG_SETMASK, &oldset, NULL);
        return 1;
    }

    // 3. Create Producer and Consumer threads
    // Pass global_dev_fd to producer thread
    if (pthread_create(&producer_tid_global, NULL, data_producer_thread, &global_dev_fd) != 0) {
        perror("[Main]: Failed to create producer thread");
        close(global_dev_fd);
        global_dev_fd = -1;
        // --- NEW: Restore signal mask before exit ---
        pthread_sigmask(SIG_SETMASK, &oldset, NULL);
        return 1;
    }
    if (pthread_create(&consumer_tid, NULL, data_consumer_thread, NULL) != 0) {
        perror("[Main]: Failed to create consumer thread");
        app_running = false; // Signal producer to exit too if consumer fails
        pthread_cond_broadcast(&data_available_cond);
        pthread_cond_broadcast(&space_available_cond);
        pthread_join(producer_tid_global, NULL); // Wait for producer to exit
        close(global_dev_fd); // Close if consumer creation fails
        global_dev_fd = -1;
        // --- NEW: Restore signal mask before exit ---
        pthread_sigmask(SIG_SETMASK, &oldset, NULL);
        return 1;
    }

    // 4. Main loop (waits for app_running to become false)
    while (app_running) {
        usleep(1000000); // Sleep for 1 second to reduce CPU usage by main thread
    }

    printf("[Main]: Signal received. Initiating shutdown...\n");

    // 5. CRITICAL STEP: Send SIGUSR1 to producer thread to unblock its read()
    printf("[Main]: Sending SIGUSR1 to producer thread (TID: %lu)...\n", (unsigned long)producer_tid_global);
    pthread_kill(producer_tid_global, SIGUSR1);

    // Give it a moment to process the signal
    usleep(10000); // 10ms


    // 6. Close the device file descriptor (after signaling, for robustness)
    if (global_dev_fd != -1) {
        close(global_dev_fd);
        printf("[Main]: Device FD closed by main thread as a fallback.\n");
        global_dev_fd = -1; // Mark as closed
    }


    // 7. Join threads to ensure they finish cleanly
    printf("[Main]: Waiting for producer thread to join...\n");
    pthread_join(producer_tid_global, NULL);
    printf("[Main]: Producer thread joined.\n");

    printf("[Main]: Waiting for consumer thread to join...\n");
    pthread_join(consumer_tid, NULL);
    printf("[Main]: Consumer thread joined.\n");

    // 8. Destroy synchronization primitives
    pthread_mutex_destroy(&user_buffer_mutex);
    pthread_cond_destroy(&data_available_cond);
    pthread_cond_destroy(&space_available_cond);

    // --- NEW: Restore original signal mask before exiting main ---
    pthread_sigmask(SIG_SETMASK, &oldset, NULL);

    printf("[Main]: Application exiting gracefully.\n");

    return 0;
}
