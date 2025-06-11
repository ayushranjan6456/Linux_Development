#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>           // Required for file_operations, register_chrdev_region, etc.
#include <linux/cdev.h>         // Required for cdev structures
#include <linux/device.h>       // Required for device_create, class_create
#include <linux/slab.h>         // Required for kmalloc, kfree
#include <linux/uaccess.h>      // Required for copy_to_user, copy_from_user
#include <linux/string.h>       // Required for strlen, strcpy, memset
#include <linux/wait.h>         // Required for wait_queue_head_t, wait_event_interruptible, wake_up_interruptible
#include <linux/sched.h>        // Required for TASK_INTERRUPTIBLE (implicit via wait.h usually)
#include <linux/errno.h>        // Required for ERESTARTSYS, EFAULT, ENOSPC etc.
#include <linux/atomic.h>       // For atomic operations on buffer pointers (good practice)

// Include our new ioctl header
#include "my_device_ioctl.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ayush Ranjan");
MODULE_DESCRIPTION("A simple dynamically loadable kernel module with Char Device, ioctl, Circular Buffer and Wait Queues");

// --- Global Variables for Character Device ---
static dev_t my_device_nbr; // Stores our device's major and minor number
static struct class* my_device_class; // Pointer to the device class
static struct cdev my_cdev; // Our character device structure

// --- Driver-specific global variables ---
#define BUFFER_CAPACITY 1024        // Max buffer size, now capacity for circular buffer
static char *circular_buffer;
static atomic_t head; // Write pointer (producer)
static atomic_t tail; // Read pointer (consumer)
static atomic_t current_data_size; // Current number of valid bytes in the buffer

// --- Wait Queue for Blocking Reads ---
static DECLARE_WAIT_QUEUE_HEAD(read_queue); // Declares and initializes a wait queue head

// --- Function Prototypes for file_operations ---
static int my_open(struct inode *inode, struct file *file);
static int my_release(struct inode *inode, struct file *file);
static ssize_t my_read(struct file *file, char __user *buf, size_t count, loff_t *offset);
static ssize_t my_write(struct file *file, const char __user *buf, size_t count, loff_t *offset);
static long my_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

// --- file_operations structure ---
static const struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = my_open,
    .release = my_release,
    .read = my_read,
    .write = my_write,
    .unlocked_ioctl = my_ioctl,
};

// --- Helper functions for Circular Buffer ---
static inline bool is_buffer_empty(void) {
    return atomic_read(&current_data_size) == 0;
}

static inline bool is_buffer_full(void) {
    return atomic_read(&current_data_size) == BUFFER_CAPACITY;
}

static inline size_t get_buffer_free_space(void) {
    return BUFFER_CAPACITY - atomic_read(&current_data_size);
}

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
    size_t bytes_read = 0;
    int ret;

    printk(KERN_INFO "My Device: Read called. Current data size: %d\n", atomic_read(&current_data_size));

    // If buffer is empty and O_NONBLOCK is NOT set, wait for data
    if (is_buffer_empty()) {
        if (file_pointer->f_flags & O_NONBLOCK) { // Check if non-blocking mode
            printk(KERN_INFO "My Device: Read - Buffer empty, non-blocking mode.\n");
            return -EAGAIN; // Resource temporarily unavailable
        }
        printk(KERN_INFO "My Device: Read - Buffer empty, waiting for data...\n");
        // Sleep until data is available or signal interrupts
        ret = wait_event_interruptible(read_queue, !is_buffer_empty());
        if (ret == -ERESTARTSYS) { // Interrupted by a signal
            printk(KERN_INFO "My Device: Read - Interrupted by signal.\n");
            return -ERESTARTSYS;
        }
        printk(KERN_INFO "My Device: Read - Woke up, data available.\n");
    }

    // Determine how much data to copy
    size_t bytes_in_buffer = atomic_read(&current_data_size);
    bytes_read = min_t(size_t, count, bytes_in_buffer);

    if (bytes_read == 0) {
        return 0; // No data to read even after waiting (e.g., if another reader took it)
    }

    // Read from circular buffer
    size_t tail_val = atomic_read(&tail);
    size_t first_part = min_t(size_t, bytes_read, BUFFER_CAPACITY - tail_val); // Bytes till end of buffer
    size_t second_part = bytes_read - first_part; // Remaining bytes from beginning of buffer

    // Copy first part (if any)
    if (copy_to_user(user_space_buffer, circular_buffer + tail_val, first_part)) {
        printk(KERN_ERR "My Device: Failed to copy first part to user space (read).\n");
        return -EFAULT;
    }
    // Copy second part (if any, for wrap-around)
    if (second_part > 0) {
        if (copy_to_user(user_space_buffer + first_part, circular_buffer, second_part)) {
            printk(KERN_ERR "My Device: Failed to copy second part to user space (read).\n");
            return -EFAULT;
        }
    }

    // Update tail pointer and current data size
    atomic_set(&tail, (tail_val + bytes_read) % BUFFER_CAPACITY);
    atomic_sub(bytes_read, &current_data_size);

    printk(KERN_INFO "My Device: Read %zu bytes. New data size: %d, New tail: %d.\n",
           bytes_read, atomic_read(&current_data_size), atomic_read(&tail));

    return bytes_read;
}

static ssize_t my_write(struct file *file_pointer, const char __user *user_space_buffer, size_t count, loff_t *offset) {
    size_t bytes_to_write = 0;
    int ret;

    printk(KERN_INFO "My Device: Write called. Current data size: %d\n", atomic_read(&current_data_size));

    // If buffer is full and O_NONBLOCK is NOT set, wait for space
    if (is_buffer_full()) {
        if (file_pointer->f_flags & O_NONBLOCK) {
            printk(KERN_INFO "My Device: Write - Buffer full, non-blocking mode.\n");
            return -EAGAIN;
        }
        printk(KERN_INFO "My Device: Write - Buffer full, waiting for space...\n");
        // Sleep until space is available or signal interrupts
        // Here we could add a write_queue if we want writers to block, for now just for readers
        // For simple demos, we'll let writers block on read_queue for simplicity, but ideally separate
        ret = wait_event_interruptible(read_queue, !is_buffer_full()); // Re-use read_queue for now
        if (ret == -ERESTARTSYS) {
            printk(KERN_INFO "My Device: Write - Interrupted by signal.\n");
            return -ERESTARTSYS;
        }
        printk(KERN_INFO "My Device: Write - Woke up, space available.\n");
    }

    // Determine how much data to copy
    size_t free_space = get_buffer_free_space();
    bytes_to_write = min_t(size_t, count, free_space);

    if (bytes_to_write == 0) {
        printk(KERN_WARNING "My Device: Write - No space to write.\n");
        return -ENOSPC; // No space left on device
    }

    // Write to circular buffer
    size_t head_val = atomic_read(&head);
    size_t first_part = min_t(size_t, bytes_to_write, BUFFER_CAPACITY - head_val); // Bytes till end of buffer
    size_t second_part = bytes_to_write - first_part; // Remaining bytes from beginning of buffer

    // Copy first part
    if (copy_from_user(circular_buffer + head_val, user_space_buffer, first_part)) {
        printk(KERN_ERR "My Device: Failed to copy first part from user space (write).\n");
        return -EFAULT;
    }
    // Copy second part (if any, for wrap-around)
    if (second_part > 0) {
        if (copy_from_user(circular_buffer, user_space_buffer + first_part, second_part)) {
            printk(KERN_ERR "My Device: Failed to copy second part from user space (write).\n");
            return -EFAULT;
        }
    }

    // Update head pointer and current data size
    atomic_set(&head, (head_val + bytes_to_write) % BUFFER_CAPACITY);
    atomic_add(bytes_to_write, &current_data_size);

    printk(KERN_INFO "My Device: Wrote %zu bytes. New data size: %d, New head: %d.\n",
           bytes_to_write, atomic_read(&current_data_size), atomic_read(&head));

    // Wake up any sleeping readers!
    wake_up_interruptible(&read_queue);

    return bytes_to_write;
}


static long my_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    int retval = 0;
    int user_val = 0; // For arguments from user space

    printk(KERN_INFO "My Device: ioctl command received: 0x%x\n", cmd);

    switch (cmd) {
        case MY_DEVICE_GET_STATUS:
            // Example: return current buffer_size as status
            retval = put_user(atomic_read(&current_data_size), (int __user *)arg);
            if (retval != 0) return -EFAULT;
            printk(KERN_INFO "My Device: GET_STATUS - returned buffer data size: %d.\n", atomic_read(&current_data_size));
            break;

        case MY_DEVICE_SET_MODE:
            // Example: set a dummy mode variable in kernel (not implemented yet)
            retval = get_user(user_val, (int __user *)arg);
            if (retval != 0) return -EFAULT;
            printk(KERN_INFO "My Device: SET_MODE - received value: %d (mode set).\n", user_val);
            // In a real driver, you'd set a static 'mode' variable here.
            break;

        case MY_DEVICE_RESET_BUFFER:
            // Reset circular buffer pointers and size
            atomic_set(&head, 0);
            atomic_set(&tail, 0);
            atomic_set(&current_data_size, 0);
            memset(circular_buffer, 0, BUFFER_CAPACITY); // Clear content
            printk(KERN_INFO "My Device: RESET_BUFFER - buffer cleared and pointers reset.\n");
            // Wake up any waiting readers if they were waiting for data, now there's none
            // Or writers if they were waiting for space (if a separate write_queue was added)
            wake_up_interruptible(&read_queue); // Notify any waiting threads
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

    // Allocate circular buffer
    circular_buffer = kmalloc(BUFFER_CAPACITY, GFP_KERNEL);
    if (!circular_buffer) {
        printk(KERN_ERR "My Device: Error allocating memory for circular buffer.\n");
        device_destroy(my_device_class, my_device_nbr);
        cdev_del(&my_cdev);
        class_destroy(my_device_class);
        unregister_chrdev_region(my_device_nbr, 1);
        return -ENOMEM;
    }
    memset(circular_buffer, 0, BUFFER_CAPACITY); // Initialize buffer to zeros

    // Initialize circular buffer pointers and size
    atomic_set(&head, 0);
    atomic_set(&tail, 0);
    atomic_set(&current_data_size, 0);

    // Write an initial message to demonstrate functionality without user writes
    const char *initial_msg = "Kernel Circular Buffer Ready!\n";
    size_t msg_len = strlen(initial_msg);
    if (msg_len < BUFFER_CAPACITY) {
        memcpy(circular_buffer, initial_msg, msg_len);
        atomic_add(msg_len, &current_data_size);
        atomic_set(&head, msg_len); // Update head after initial write
        printk(KERN_INFO "My Device: Initial message added to buffer.\n");
    }

    printk(KERN_INFO "My Device: Module loaded successfully.\n");
    return 0;
}

static void __exit my_module_exit(void) {
    printk(KERN_INFO "My Device: Exiting module.\n");

    device_destroy(my_device_class, my_device_nbr);
    cdev_del(&my_cdev);
    class_destroy(my_device_class);
    unregister_chrdev_region(my_device_nbr, 1);
    kfree(circular_buffer);

    printk(KERN_INFO "My Device: Module unloaded.\n");
}

module_init(my_module_init);
module_exit(my_module_exit);
