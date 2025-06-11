#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>      // For open(), O_RDWR, O_NONBLOCK
#include <unistd.h>     // For close(), read(), write()
#include <sys/ioctl.h>  // For ioctl()
#include <errno.h>      // For errno

// Include the shared ioctl header
#include "my_device_ioctl.h"

#define DEVICE_PATH "/dev/my_device_node"
#define READ_BUF_SIZE 256

int main() {
    int fd;
    char read_buf[READ_BUF_SIZE];
    int ret;
    int status_val;
    int set_mode_val = 123;

    printf("--- Testing Character Device: %s ---\n", DEVICE_PATH);

    // 1. Open the device
    // We'll open it in blocking mode by default for read demo
    fd = open(DEVICE_PATH, O_RDWR);
    if (fd < 0) {
        perror("Failed to open device");
        return 1;
    }
    printf("Successfully opened device %s (fd: %d)\n", DEVICE_PATH, fd);

    // --- DEMO BLOCKING READ ---
    printf("\n--- Demonstrating Blocking Read (this will wait for data) ---\n");
    printf("Open another terminal and write to the device: echo 'DATA' > %s\n", DEVICE_PATH);
    printf("Waiting for data (press Ctrl+C to interrupt if needed)...\n");

    memset(read_buf, 0, READ_BUF_SIZE);
    ret = read(fd, read_buf, READ_BUF_SIZE - 1); // This will block if no data
    if (ret < 0) {
        perror("Failed to read from device (blocking)");
        if (errno == ERESTART) {
            printf("Read was interrupted by a signal.\n");
        }
        close(fd);
        return 1;
    }
    read_buf[ret] = '\0';
    printf("Read %d bytes: \"%s\"\n", ret, read_buf);
    printf("--- End of Blocking Read Demo ---\n");

    // After blocking read, subsequent operations
    // 2. Write a new message
    printf("\nAttempting to write to device...\n");
    const char *write_data = "Hello from User Space!";
    ret = write(fd, write_data, strlen(write_data));
    if (ret < 0) {
        perror("Failed to write to device");
        close(fd);
        return 1;
    }
    printf("Wrote %d bytes: \"%s\"\n", ret, write_data);

    // 3. Test ioctl: MY_DEVICE_GET_STATUS
    printf("\nTesting MY_DEVICE_GET_STATUS ioctl...\n");
    ret = ioctl(fd, MY_DEVICE_GET_STATUS, &status_val);
    if (ret < 0) {
        perror("Failed to perform MY_DEVICE_GET_STATUS ioctl");
        close(fd);
        return 1;
    }
    printf("MY_DEVICE_GET_STATUS result: %d (Current buffer data size)\n", status_val);

    // 4. Test ioctl: MY_DEVICE_SET_MODE
    printf("\nTesting MY_DEVICE_SET_MODE ioctl (setting mode to %d)...\n", set_mode_val);
    ret = ioctl(fd, MY_DEVICE_SET_MODE, &set_mode_val);
    if (ret < 0) {
        perror("Failed to perform MY_DEVICE_SET_MODE ioctl");
        close(fd);
        return 1;
    }
    printf("MY_DEVICE_SET_MODE successful.\n");

    // 5. Test ioctl: MY_DEVICE_RESET_BUFFER
    printf("\nTesting MY_DEVICE_RESET_BUFFER ioctl...\n");
    ret = ioctl(fd, MY_DEVICE_RESET_BUFFER); // No argument needed
    if (ret < 0) {
        perror("Failed to perform MY_DEVICE_RESET_BUFFER ioctl");
        close(fd);
        return 1;
    }
    printf("MY_DEVICE_RESET_BUFFER successful.\n");

    // Read after buffer reset (should likely block again if nothing written)
    printf("\nAttempting to read after buffer reset (should block or show empty)...\n");
    memset(read_buf, 0, READ_BUF_SIZE);
    ret = read(fd, read_buf, READ_BUF_SIZE - 1);
    if (ret < 0) {
        perror("Failed to read after reset");
        if (errno == ERESTART) {
            printf("Read was interrupted by a signal.\n");
        }
        close(fd);
        return 1;
    }
    read_buf[ret] = '\0';
    printf("Read %d bytes: \"%s\"\n", ret, read_buf);


    // Close the device
    close(fd);
    printf("\nDevice closed.\n");

    return 0;
}
