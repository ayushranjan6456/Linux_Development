#ifndef MY_DEVICE_IOCTL_H
#define MY_DEVICE_IOCTL_H

#include <linux/ioctl.h> // Required for _IO, _IOW, etc.

// Define a magic number for your device
#define MY_DEVICE_MAGIC 'k' // Choose a unique character

// Define your ioctl commands
// _IO(type, nr) - No arguments
// _IOW(type, nr, data_type) - Write argument from user to kernel
// _IOR(type, nr, data_type) - Read argument from kernel to user
// _IOWR(type, nr, data_type) - Both write and read

#define MY_DEVICE_GET_STATUS     _IOR(MY_DEVICE_MAGIC, 1, int)
#define MY_DEVICE_SET_MODE       _IOW(MY_DEVICE_MAGIC, 2, int)
#define MY_DEVICE_RESET_BUFFER   _IO(MY_DEVICE_MAGIC, 3)

#endif // MY_DEVICE_IOCTL_H