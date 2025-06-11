#ifndef MY_DEVICE_IOCTL_H
#define MY_DEVICE_IOCTL_H

#include <linux/ioctl.h>

// Define a magic number for your device
#define MY_DEVICE_MAGIC 'D' // 'D' for Device

// Define your IOCTL commands
#define MY_DEVICE_IOCTL_GET_STATUS   _IOR(MY_DEVICE_MAGIC, 1, int)
#define MY_DEVICE_IOCTL_CLEAR_BUFFER _IO(MY_DEVICE_MAGIC, 2)

#endif // MY_DEVICE_IOCTL_H
