#ifndef MY_DEVICE_IOCTL_H
#define MY_DEVICE_IOCTL_H

#include <linux/ioctl.h> // For _IOR, _IOW, _IO macros

// Define a magic number for your device
#define MY_DEVICE_MAGIC 'k'

// New: Struct to return buffer status (current data size and total capacity)
typedef struct {
    int current_data_size;
    int buffer_capacity;
} my_device_status_t;

// Define your ioctl commands
// Changed: MY_DEVICE_IOCTL_GET_STATUS now returns my_device_status_t
#define MY_DEVICE_IOCTL_GET_STATUS     _IOR(MY_DEVICE_MAGIC, 1, my_device_status_t)
#define MY_DEVICE_IOCTL_CLEAR_BUFFER   _IO(MY_DEVICE_MAGIC, 2)
// New: Command to set buffer capacity
#define MY_DEVICE_IOCTL_SET_CAPACITY   _IOW(MY_DEVICE_MAGIC, 3, int) // Write an int (new capacity)

#endif // MY_DEVICE_IOCTL_H
