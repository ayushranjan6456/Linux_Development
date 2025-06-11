#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>           // Required for file_operations, register_chrdev_region, etc.
#include <linux/cdev.h>         // Required for cdev structures
#include <linux/device.h>       // Required for device_create, class_create
#include <linux/slab.h>         // Required for kmalloc, kfree
#include <linux/uaccess.h>      // Required for copy_to_user, copy_from_user
#include <linux/string.h>       // Required for strlen, strcpy

// Include our new ioctl header
#include "my_device_ioctl.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ayush Ranjan");
MODULE_DESCRIPTION("A simple dynamically loadable kernel module with Char Device and ioctl");

// --- Global Variables for Character Device ---
static dev_t my_device_nbr; // Stores our device's major and minor number
static struct class* my_device_class; // Pointer to the device class
static struct cdev my_cdev; // Our character device structure

// --- Driver-specific global variables ---
static char *kernel_buffer;
static ssize_t buffer_size = 0; // Current data size in buffer
#define BUFFER_SIZE 1024        // Max buffer size

// --- Function Prototypes for file_operations ---
static int my_open(struct inode *inode, struct file *file);
static int my_release(struct inode *inode, struct file *file);
static ssize_t my_read(struct file *file, char __user *buf, size_t count, loff_t *offset);
static ssize_t my_write(struct file *file, const char __user *buf, size_t count, loff_t *offset);
static long my_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

// --- file_operations structure ---
// This replaces the old proc_ops
static const struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = my_open,
    .release = my_release,
    .read = my_read,
    .write = my_write,
    .unlocked_ioctl = my_ioctl, // For ioctl commands
};

// --- Driver Function Implementations ---

static int my_open(struct inode *inode, struct file *file) {
    printk(KERN_INFO "My Device: Opened device.\n");
    return 0;
}

static int my_release(struct inode *inode, struct file *file) {
    printk(KERN_INFO "My Device: Released device.\n");
    return 0;
}

static ssize_t my_read(struct file *file_pointer, char __user *user_space_buffer, size_t count, loff_t *offset) {
    if (*offset >= buffer_size) {
        return 0; // End of file
    }

    size_t bytes_to_copy = min_t(size_t, count, buffer_size - *offset);
    if (bytes_to_copy == 0) {
        return 0;
    }

    int result = copy_to_user(user_space_buffer, kernel_buffer + *offset, bytes_to_copy);

    if (result != 0) {
        printk(KERN_ERR "My Device: Failed to copy %d bytes to user space (read).\n", result);
        return -EFAULT; // Bad address
    }

    *offset += bytes_to_copy;
    printk(KERN_INFO "My Device: Read %zu bytes from kernel buffer.\n", bytes_to_copy);
    return bytes_to_copy;
}

static ssize_t my_write(struct file *file_pointer, const char __user *user_space_buffer, size_t count, loff_t *offset) {
    // Current simple write: append/overwrite from start if offset is 0.
    // For character devices, usually, writes don't use offset extensively for simple buffers.
    // We'll treat this as appending for now, or overwriting if total size exceeds BUFFER_SIZE
    
    if (count == 0) return 0;

    // Limit incoming data to avoid overflow, leave space for null terminator
    size_t bytes_to_write = min_t(size_t, count, BUFFER_SIZE - 1);
    if (bytes_to_write == 0) {
        printk(KERN_WARNING "My Device: Buffer full, cannot write more data.\n");
        return -ENOSPC; // No space left on device
    }

    // If existing content + new content overflows, either truncate or reset
    // For simplicity now, let's just make sure we don't write past BUFFER_SIZE
    if (buffer_size + bytes_to_write > BUFFER_SIZE -1) {
        bytes_to_write = BUFFER_SIZE -1 - buffer_size;
        if (bytes_to_write <= 0) { // Already full or no space left for even 1 char
            printk(KERN_WARNING "My Device: No space to write.\n");
            return -ENOSPC;
        }
    }

    int result = copy_from_user(kernel_buffer + buffer_size, user_space_buffer, bytes_to_write);

    if (result != 0) {
        printk(KERN_ERR "My Device: Failed to copy %d bytes from user space (write).\n", result);
        return -EFAULT; // Bad address
    }

    buffer_size += bytes_to_write;
    kernel_buffer[buffer_size] = '\0'; // Null-terminate after writing

    printk(KERN_INFO "My Device: Received %zu bytes from user: '%s'\n", bytes_to_write, kernel_buffer);
    return bytes_to_write;
}


static long my_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    int retval = 0;
    int user_val = 0; // For arguments from user space

    printk(KERN_INFO "My Device: ioctl command received: 0x%x\n", cmd);

    switch (cmd) {
        case MY_DEVICE_GET_STATUS:
            // Example: return current buffer_size as status
            retval = put_user(buffer_size, (int __user *)arg);
            if (retval != 0) return -EFAULT;
            printk(KERN_INFO "My Device: GET_STATUS - returned buffer size: %zu.\n", buffer_size);
            break;

        case MY_DEVICE_SET_MODE:
            // Example: set a dummy mode variable in kernel (not implemented yet)
            retval = get_user(user_val, (int __user *)arg);
            if (retval != 0) return -EFAULT;
            printk(KERN_INFO "My Device: SET_MODE - received value: %d (mode set).\n", user_val);
            // In a real driver, you'd set a static 'mode' variable here.
            break;

        case MY_DEVICE_RESET_BUFFER:
            memset(kernel_buffer, 0, BUFFER_SIZE); // Clear buffer content
            buffer_size = 0; // Reset size
            printk(KERN_INFO "My Device: RESET_BUFFER - buffer cleared.\n");
            break;

        default:
            printk(KERN_WARNING "My Device: Unknown ioctl command 0x%x.\n", cmd);
            return -ENOTTY; // Inappropriate ioctl for device
    }
    return 0; // Success
}

// --- Module Initialization & Exit ---

static int __init my_module_init(void) {
    int ret;
    printk(KERN_INFO "My Device: Initializing character device module.\n");

    // 1. Allocate a major/minor number range
    ret = alloc_chrdev_region(&my_device_nbr, 0, 1, "my_device");
    if (ret < 0) {
        printk(KERN_ERR "My Device: Failed to allocate char dev region (%d).\n", ret);
        return ret;
    }
    printk(KERN_INFO "My Device: Allocated device number Major: %d Minor: %d\n", MAJOR(my_device_nbr), MINOR(my_device_nbr));

    // 2. Create a device class (will appear in /sys/class/)
    my_device_class = class_create("my_device_class");
    if (IS_ERR(my_device_class)) {
        printk(KERN_ERR "My Device: Failed to create device class.\n");
        unregister_chrdev_region(my_device_nbr, 1);
        return PTR_ERR(my_device_class);
    }

    // 3. Initialize the cdev structure and add it to the kernel
    cdev_init(&my_cdev, &fops);
    my_cdev.owner = THIS_MODULE;
    ret = cdev_add(&my_cdev, my_device_nbr, 1);
    if (ret < 0) {
        printk(KERN_ERR "My Device: Failed to add cdev.\n");
        class_destroy(my_device_class);
        unregister_chrdev_region(my_device_nbr, 1);
        return ret;
    }

    // 4. Create the device file (will appear in /dev/)
    // This creates /dev/my_device_node
    if (IS_ERR(device_create(my_device_class, NULL, my_device_nbr, NULL, "my_device_node"))) {
        printk(KERN_ERR "My Device: Failed to create device.\n");
        cdev_del(&my_cdev);
        class_destroy(my_device_class);
        unregister_chrdev_region(my_device_nbr, 1);
        return -1;
    }
    printk(KERN_INFO "My Device: Device file created at /dev/my_device_node\n");

    // Allocate kernel buffer
    kernel_buffer = kmalloc(BUFFER_SIZE, GFP_KERNEL);
    if (!kernel_buffer) {
        printk(KERN_ERR "My Device: Error allocating memory for kernel buffer.\n");
        device_destroy(my_device_class, my_device_nbr);
        cdev_del(&my_cdev);
        class_destroy(my_device_class);
        unregister_chrdev_region(my_device_nbr, 1);
        return -ENOMEM;
    }
    memset(kernel_buffer, 0, BUFFER_SIZE); // Initialize buffer to zeros
    strcpy(kernel_buffer, "Hello From Kernel Char Device!\n");
    buffer_size = strlen(kernel_buffer);

    printk(KERN_INFO "My Device: Module loaded successfully.\n");
    return 0;
}

static void __exit my_module_exit(void) {
    printk(KERN_INFO "My Device: Exiting module.\n");

    device_destroy(my_device_class, my_device_nbr);
    cdev_del(&my_cdev);
    class_destroy(my_device_class);
    unregister_chrdev_region(my_device_nbr, 1);
    kfree(kernel_buffer);

    printk(KERN_INFO "My Device: Module unloaded.\n");
}

module_init(my_module_init);
module_exit(my_module_exit);
