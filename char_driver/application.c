#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>      // For open()
#include <unistd.h>     // For close(), read(), write()
#include <sys/ioctl.h>  // For ioctl()

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
    fd = open(DEVICE_PATH, O_RDWR); // Open for Read and Write
    if (fd < 0) {
        perror("Failed to open device");
        return 1;
    }
    printf("Successfully opened device %s (fd: %d)\n", DEVICE_PATH, fd);

    // 2. Read initial message
    printf("\nAttempting to read from device...\n");
    memset(read_buf, 0, READ_BUF_SIZE); // Clear buffer
    ret = read(fd, read_buf, READ_BUF_SIZE - 1); // Read up to buf size - 1 for null terminator
    if (ret < 0) {
        perror("Failed to read from device");
        close(fd);
        return 1;
    }
    read_buf[ret] = '\0'; // Null-terminate the string
    printf("Read %d bytes: \"%s\"\n", ret, read_buf);

    // 3. Write a new message
    printf("\nAttempting to write to device...\n");
    const char *write_data = "Hello from User Space!";
    ret = write(fd, write_data, strlen(write_data));
    if (ret < 0) {
        perror("Failed to write to device");
        close(fd);
        return 1;
    }
    printf("Wrote %d bytes: \"%s\"\n", ret, write_data);

    // 4. Read updated message (or read again, offset will be at end from previous read)
    // To read from start again, you'd usually lseek, but for simple buffer driver,
    // subsequent read might return 0 if all data read unless offset is reset by driver or lseek.
    // Let's reset offset for this demo.
    lseek(fd, 0, SEEK_SET); // Reset read offset to beginning
    printf("\nAttempting to read updated message from device (after seek)...\n");
    memset(read_buf, 0, READ_BUF_SIZE);
    ret = read(fd, read_buf, READ_BUF_SIZE - 1);
    if (ret < 0) {
        perror("Failed to read from device (after seek)");
        close(fd);
        return 1;
    }
    read_buf[ret] = '\0';
    printf("Read %d bytes: \"%s\"\n", ret, read_buf);


    // 5. Test ioctl: MY_DEVICE_GET_STATUS
    printf("\nTesting MY_DEVICE_GET_STATUS ioctl...\n");
    ret = ioctl(fd, MY_DEVICE_GET_STATUS, &status_val);
    if (ret < 0) {
        perror("Failed to perform MY_DEVICE_GET_STATUS ioctl");
        close(fd);
        return 1;
    }
    printf("MY_DEVICE_GET_STATUS result: %d (Expected buffer size)\n", status_val);

    // 6. Test ioctl: MY_DEVICE_SET_MODE
    printf("\nTesting MY_DEVICE_SET_MODE ioctl (setting mode to %d)...\n", set_mode_val);
    ret = ioctl(fd, MY_DEVICE_SET_MODE, &set_mode_val);
    if (ret < 0) {
        perror("Failed to perform MY_DEVICE_SET_MODE ioctl");
        close(fd);
        return 1;
    }
    printf("MY_DEVICE_SET_MODE successful.\n");

    // 7. Test ioctl: MY_DEVICE_RESET_BUFFER
    printf("\nTesting MY_DEVICE_RESET_BUFFER ioctl...\n");
    ret = ioctl(fd, MY_DEVICE_RESET_BUFFER); // No argument needed
    if (ret < 0) {
        perror("Failed to perform MY_DEVICE_RESET_BUFFER ioctl");
        close(fd);
        return 1;
    }
    printf("MY_DEVICE_RESET_BUFFER successful.\n");

    // 8. Read after buffer reset (should be empty or initial message)
    lseek(fd, 0, SEEK_SET); // Reset read offset to beginning
    printf("\nAttempting to read after buffer reset...\n");
    memset(read_buf, 0, READ_BUF_SIZE);
    ret = read(fd, read_buf, READ_BUF_SIZE - 1);
    if (ret < 0) {
        perror("Failed to read after reset");
        close(fd);
        return 1;
    }
    read_buf[ret] = '\0';
    printf("Read %d bytes: \"%s\"\n", ret, read_buf);


    // 9. Close the device
    close(fd);
    printf("\nDevice closed.\n");

    return 0;
}
