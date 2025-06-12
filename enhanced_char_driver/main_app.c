#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>    // For open(), O_RDWR, O_NONBLOCK
#include <unistd.h>   // For read(), write(), close(), usleep()
#include <string.h>   // For strlen(), memset()
#include <pthread.h>  // For pthreads
#include <errno.h>    // For errno
#include <signal.h>   // For signal handling
#include <stdbool.h>  // For bool type
#include <sys/ioctl.h> // For ioctl()
#include <getopt.h>   // For getopt_long()
#include <sched.h>    // For real-time scheduling

// Include our custom ioctl header
#include "my_device_ioctl.h"

#define DEVICE_PATH "/dev/my_device_node"
#define USER_BUFFER_CAPACITY 64 // Capacity of the user-space circular buffer
#define DATA_BLOCK_SIZE 32      // Size of data blocks to read/write

// --- Global Variables ---
static volatile bool app_running = true; // Flag to control thread execution and main loop
static int global_dev_fd = -1;           // File descriptor for the kernel device

// Global thread IDs for signalling
static pthread_t producer_tid_global;
static pthread_t consumer_tid;

// --- User-space Circular Buffer and Synchronization ---
typedef struct {
    char data[DATA_BLOCK_SIZE];
    size_t len;
} data_block_t;

static data_block_t user_circular_buffer[USER_BUFFER_CAPACITY];
static volatile int user_head = 0; // Write pointer for user buffer
static volatile int user_tail = 0; // Read pointer for user buffer
static volatile int user_count = 0; // Current number of items in user buffer

static pthread_mutex_t user_buffer_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t data_available_cond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t space_available_cond = PTHREAD_COND_INITIALIZER;

// Real-time scheduling parameters
static int producer_rt_priority = 50; // Default priority
static int consumer_rt_priority = 49; // Default priority

// --- Signal Handler for Graceful Shutdown ---
void sig_handler(int signo) {
    if (signo == SIGINT || signo == SIGTERM) {
        printf("\n[User App] Caught signal %d. Initiating graceful shutdown...\n", signo);
        app_running = false; // Set the flag to stop threads
        // Wake up any waiting threads to let them see app_running change
        pthread_cond_broadcast(&data_available_cond);
        pthread_cond_broadcast(&space_available_cond);
        // If the producer is stuck in a blocking kernel read, send it a signal
        // This will cause the read() to return -1 with errno = EINTR
        if (producer_tid_global) {
            pthread_kill(producer_tid_global, SIGUSR1);
        }
    }
}

// --- User-space Circular Buffer Helper Functions ---
bool user_buffer_is_empty() {
    return user_count == 0;
}

bool user_buffer_is_full() {
    return user_count == USER_BUFFER_CAPACITY;
}

// --- Producer Thread Function ---
void *data_producer_thread(void *arg) {
    int dev_fd = *(int *)arg;
    char kernel_read_buffer[DATA_BLOCK_SIZE];
    ssize_t bytes_read;
    int ret;

    printf("[Producer] Thread started. TID: %lu\n", (unsigned long)pthread_self());

    // Set real-time scheduling for producer thread
    struct sched_param param;
    param.sched_priority = producer_rt_priority;
    ret = pthread_setschedparam(pthread_self(), SCHED_FIFO, &param);
    if (ret != 0) {
        perror("[Producer] Failed to set real-time scheduling for producer. Run with sudo/root?");
        printf("[Producer] errno: %d\n", errno);
    } else {
        printf("[Producer] Set SCHED_FIFO priority to %d.\n", producer_rt_priority);
    }

    // Unblock SIGUSR1 for this thread if it was blocked by main
    sigset_t set, oldset;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    pthread_sigmask(SIG_UNBLOCK, &set, &oldset);

    while (app_running) {
        // Read from kernel device
        memset(kernel_read_buffer, 0, DATA_BLOCK_SIZE);
        bytes_read = read(dev_fd, kernel_read_buffer, DATA_BLOCK_SIZE);

        if (bytes_read < 0) {
            if (errno == EINTR) {
                printf("[Producer] Read interrupted by signal (EINTR). Exiting gracefully.\n");
                goto producer_exit; // Jump to cleanup
            } else if (errno == EAGAIN) { // Non-blocking, no data yet (shouldn't happen with blocking reads)
                usleep(10000); // Small delay to prevent busy-waiting
                continue;
            } else {
                perror("[Producer] Error reading from device");
                goto producer_exit;
            }
        } else if (bytes_read == 0) {
            // EOF or device closed, unlikely for char dev unless module is unloaded
            printf("[Producer] Read returned 0 bytes (EOF/Device Closed). Exiting.\n");
            goto producer_exit;
        } else {
            printf("[Producer] Read %zd bytes from kernel device: '%.*s'\n",
                   bytes_read, (int)bytes_read, kernel_read_buffer);

            // Add data to user-space circular buffer
            pthread_mutex_lock(&user_buffer_mutex);

            // Wait if user buffer is full
            while (user_buffer_is_full() && app_running) {
                printf("[Producer] User buffer full. Waiting for space...\n");
                pthread_cond_wait(&space_available_cond, &user_buffer_mutex);
            }

            if (!app_running) { // Check app_running again after waking up
                pthread_mutex_unlock(&user_buffer_mutex);
                goto producer_exit;
            }

            // Copy data to user-space buffer
            memcpy(user_circular_buffer[user_head].data, kernel_read_buffer, bytes_read);
            user_circular_buffer[user_head].len = bytes_read;
            user_head = (user_head + 1) % USER_BUFFER_CAPACITY;
            user_count++;
            printf("[Producer] Added %zd bytes to user buffer. Count: %d\n", bytes_read, user_count);

            pthread_cond_signal(&data_available_cond); // Signal consumer that data is available
            pthread_mutex_unlock(&user_buffer_mutex);
        }
        usleep(50000); // Small delay to simulate work/avoid spinning
    }

producer_exit:
    printf("[Producer] Exiting thread.\n");
    pthread_sigmask(SIG_SETMASK, &oldset, NULL); // Restore original signal mask
    return NULL;
}

// --- Consumer Thread Function ---
void *data_consumer_thread(void *arg) {
    data_block_t current_block;
    int ret;

    printf("[Consumer] Thread started. TID: %lu\n", (unsigned long)pthread_self());

    // Set real-time scheduling for consumer thread
    struct sched_param param;
    param.sched_priority = consumer_rt_priority;
    ret = pthread_setschedparam(pthread_self(), SCHED_FIFO, &param);
    if (ret != 0) {
        perror("[Consumer] Failed to set real-time scheduling for consumer. Run with sudo/root?");
        printf("[Consumer] errno: %d\n", errno);
    } else {
        printf("[Consumer] Set SCHED_FIFO priority to %d.\n", consumer_rt_priority);
    }

    while (app_running) {
        pthread_mutex_lock(&user_buffer_mutex);

        // Wait if user buffer is empty
        while (user_buffer_is_empty() && app_running) {
            printf("[Consumer] User buffer empty. Waiting for data...\n");
            pthread_cond_wait(&data_available_cond, &user_buffer_mutex);
        }

        if (!app_running) { // Check app_running again after waking up
            pthread_mutex_unlock(&user_buffer_mutex);
            goto consumer_exit;
        }

        // Retrieve data from user-space buffer
        memcpy(&current_block, &user_circular_buffer[user_tail], sizeof(data_block_t));
        user_tail = (user_tail + 1) % USER_BUFFER_CAPACITY;
        user_count--;
        printf("[Consumer] Processed %zd bytes from user buffer: '%.*s'. Count: %d\n",
               current_block.len, (int)current_block.len, current_block.data, user_count);

        pthread_cond_signal(&space_available_cond); // Signal producer that space is available
        pthread_mutex_unlock(&user_buffer_mutex);

        usleep(100000); // Simulate processing time (100ms)
    }

consumer_exit:
    printf("[Consumer] Exiting thread.\n");
    return NULL;
}

// --- Utility Functions for CLI ---

void display_usage(char *prog_name) {
    printf("Usage: %s [OPTIONS]\n", prog_name);
    printf("Interact with the /dev/my_device_node kernel module.\n\n");
    printf("Options:\n");
    printf("  -s, --status              Query and display kernel buffer status.\n");
    printf("  -c, --clear               Clear the kernel module's circular buffer.\n");
    printf("  -S, --set-capacity <size> Set kernel buffer capacity (bytes). Buffer must be empty.\n");
    printf("  -r, --run                 Start producer/consumer threads and run application.\n");
    printf("  -P, --priority-producer <prio> Set real-time priority for producer (1-99). Default: %d\n", producer_rt_priority);
    printf("  -C, --priority-consumer <prio> Set real-time priority for consumer (1-99). Default: %d\n", consumer_rt_priority);
    printf("  -e, --exit                Exit immediately after processing other commands.\n");
    printf("  -h, --help                Display this help message.\n");
    printf("\nNote: '--run' or passing no options will start the producer/consumer threads by default.\n");
    printf("      Real-time priorities and capacity changes require running with sudo/root.\n");
}

void query_kernel_status() {
    my_device_status_t status_info; // Use the new struct
    if (global_dev_fd < 0) {
        printf("[CLI] Device not open. Cannot query status.\n");
        return;
    }
    memset(&status_info, 0, sizeof(status_info)); // Clear struct before ioctl

    if (ioctl(global_dev_fd, MY_DEVICE_IOCTL_GET_STATUS, &status_info) == -1) {
        perror("[CLI] IOCTL GET_STATUS failed");
    } else {
        printf("[CLI] Kernel buffer status: %d / %d bytes currently in use.\n",
               status_info.current_data_size, status_info.buffer_capacity);
    }
}

void clear_kernel_buffer() {
    if (global_dev_fd < 0) {
        printf("[CLI] Device not open. Cannot clear buffer.\n");
        return;
    }
    if (ioctl(global_dev_fd, MY_DEVICE_IOCTL_CLEAR_BUFFER) == -1) {
        perror("[CLI] IOCTL CLEAR_BUFFER failed");
    } else {
        printf("[CLI] Kernel buffer cleared.\n");
    }
}

void set_kernel_capacity(int new_capacity) {
    if (global_dev_fd < 0) {
        printf("[CLI] Device not open. Cannot set capacity.\n");
        return;
    }
    printf("[CLI] Attempting to set kernel buffer capacity to %d bytes...\n", new_capacity);
    if (ioctl(global_dev_fd, MY_DEVICE_IOCTL_SET_CAPACITY, &new_capacity) == -1) {
        perror("[CLI] IOCTL SET_CAPACITY failed");
        if (errno == EBUSY) {
            printf("[CLI] Hint: Buffer must be empty to change capacity. Try --clear first.\n");
        } else if (errno == EINVAL) {
            printf("[CLI] Hint: Invalid capacity requested (e.g., <= 0 or too large).\n");
        }
    } else {
        printf("[CLI] Kernel buffer capacity set successfully to %d bytes.\n", new_capacity);
    }
}


// --- Main Application Entry Point ---
int main(int argc, char *argv[]) {
    // Block SIGUSR1 for main thread so only producer thread gets it
    sigset_t set, oldset;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    pthread_sigmask(SIG_BLOCK, &set, &oldset);

    signal(SIGINT, sig_handler);  // Register signal handler for Ctrl+C
    signal(SIGTERM, sig_handler); // Register signal handler for termination signals

    printf("[User App] Opening device: %s\n", DEVICE_PATH);
    // Open in blocking mode, as we use wait queues in kernel for blocking
    global_dev_fd = open(DEVICE_PATH, O_RDWR);
    if (global_dev_fd < 0) {
        perror("[User App] Failed to open device");
        pthread_sigmask(SIG_SETMASK, &oldset, NULL); // Restore signal mask
        return EXIT_FAILURE;
    }

    bool run_threads = false;
    bool exit_immediately = false;

    // Command-line options parsing
    static struct option long_options[] = {
        {"status", no_argument, 0, 's'},
        {"clear", no_argument, 0, 'c'},
        {"set-capacity", required_argument, 0, 'S'}, // New option
        {"run", no_argument, 0, 'r'},
        {"priority-producer", required_argument, 0, 'P'},
        {"priority-consumer", required_argument, 0, 'C'},
        {"exit", no_argument, 0, 'e'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    int long_index = 0;
    while ((opt = getopt_long(argc, argv, "scerhP:C:S:", long_options, &long_index)) != -1) {
        switch (opt) {
            case 's':
                query_kernel_status();
                break;
            case 'c':
                clear_kernel_buffer();
                break;
            case 'S': // Handle new set capacity option
                set_kernel_capacity(atoi(optarg));
                break;
            case 'r':
                run_threads = true;
                break;
            case 'P':
                producer_rt_priority = atoi(optarg);
                if (producer_rt_priority < 1 || producer_rt_priority > 99) {
                    fprintf(stderr, "[CLI] Warning: Producer priority out of range (1-99). Using default %d.\n", producer_rt_priority);
                    producer_rt_priority = 50; // Fallback to default
                }
                break;
            case 'C':
                consumer_rt_priority = atoi(optarg);
                 if (consumer_rt_priority < 1 || consumer_rt_priority > 99) {
                    fprintf(stderr, "[CLI] Warning: Consumer priority out of range (1-99). Using default %d.\n", consumer_rt_priority);
                    consumer_rt_priority = 49; // Fallback to default
                }
                break;
            case 'e':
                exit_immediately = true;
                break;
            case 'h':
                display_usage(argv[0]);
                goto cleanup; // Go to cleanup and exit
            case '?': // Unknown option or missing argument for option
                display_usage(argv[0]);
                goto cleanup;
            default:
                break;
        }
    }

    // If no specific run command given, default to running threads
    if (!run_threads && !exit_immediately) {
        run_threads = true;
    }

    if (run_threads) {
        printf("[User App] Starting producer and consumer threads...\n");

        // Create producer thread
        if (pthread_create(&producer_tid_global, NULL, data_producer_thread, &global_dev_fd) != 0) {
            perror("[User App] Failed to create producer thread");
            app_running = false;
            goto cleanup;
        }

        // Create consumer thread
        if (pthread_create(&consumer_tid, NULL, data_consumer_thread, NULL) != 0) {
            perror("[User App] Failed to create consumer thread");
            app_running = false;
            pthread_cancel(producer_tid_global); // Try to cancel producer if consumer fails
            goto cleanup;
        }

        printf("[User App] Application is running. Press Ctrl+C to stop.\n");

        // Keep main thread alive until shutdown requested
        while (app_running) {
            sleep(1); // Sleep to avoid busy-waiting, signal handler will wake up
        }

        printf("[User App] Waiting for threads to finish...\n");
        pthread_join(producer_tid_global, NULL);
        pthread_join(consumer_tid, NULL);
        printf("[User App] All threads joined.\n");
    }

cleanup:
    printf("[User App] Performing cleanup.\n");
    // Destroy mutex and condition variables
    pthread_mutex_destroy(&user_buffer_mutex);
    pthread_cond_destroy(&data_available_cond);
    pthread_cond_destroy(&space_available_cond);

    if (global_dev_fd != -1) {
        close(global_dev_fd); // Close the device file
        printf("[User App] Device closed.\n");
    }

    pthread_sigmask(SIG_SETMASK, &oldset, NULL); // Restore original signal mask
    printf("[User App] Exiting.\n");
    return EXIT_SUCCESS;
}
