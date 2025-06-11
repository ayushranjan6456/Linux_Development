#include <linux/module.h>
#include <linux/init.h>      // For __init, __exit
#include <linux/fs.h>        // For file_operations, register_chrdev_region, etc.
#include <linux/cdev.h>      // For cdev structures
#include <linux/device.h>    // <--- CRITICAL: For class_create, device_create, class_destroy, device_destroy
#include <linux/slab.h>      // For kmalloc, kfree
#include <linux/uaccess.h>   // For copy_to_user, copy_from_user
#include <linux/string.h>    // For strlen, strcpy, memset, memcpy
#include <linux/wait.h>      // For wait_queue_head_t, wait_event_interruptible, wake_up_interruptible
#include <linux/sched.h>     // For current->comm (to print task name in dmesg)
#include <linux/errno.h>     // For EINTR, ERESTARTSYS, EFAULT, ENOSPC etc.
#include <linux/atomic.h>    // For atomic_t and atomic operations

// Include our new ioctl header
#include "my_device_ioctl.h" // Assuming it's in the same directory or properly included

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ayush Ranjan"); // Please change to your name
MODULE_DESCRIPTION("A Linux character device with circular buffer, wait queues, and ioctl commands.");
MODULE_VERSION("0.2"); // Updated version for this stage

#define DEVICE_NAME "my_device_node"
#define CLASS_NAME "my_device_class"

// --- Global Variables for Character Device ---
static dev_t my_device_nbr; // Stores our device's major and minor number
static struct class* my_device_class = NULL; // Pointer to the device class
static struct cdev my_cdev; // Our character device structure
static struct device* my_device_device = NULL; // Pointer to the device created in /dev/

// --- Driver-specific global variables ---
#define BUFFER_CAPACITY 256          // Max buffer size for circular buffer
static char *circular_buffer;
static atomic_t head; // Write pointer (producer)
static atomic_t tail; // Read pointer (consumer)
static atomic_t current_data_size; // Current number of valid bytes in the buffer

// --- Wait Queues for Blocking I/O ---
static DECLARE_WAIT_QUEUE_HEAD(read_queue);  // For readers waiting for data
static DECLARE_WAIT_QUEUE_HEAD(write_queue); // For writers waiting for space (optional, but good for completeness)

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

// Internal helper for adding data (used by write and simulated interrupt)
static void add_data_to_circular_buffer(const char *data, size_t len) {
    size_t bytes_to_copy = min_t(size_t, len, get_buffer_free_space());
    size_t first_part_len = min_t(size_t, bytes_to_copy, BUFFER_CAPACITY - atomic_read(&head));
    size_t second_part_len = bytes_to_copy - first_part_len;

    memcpy(circular_buffer + atomic_read(&head), data, first_part_len);
    if (second_part_len > 0) {
        memcpy(circular_buffer, data + first_part_len, second_part_len);
    }
    atomic_set(&head, (atomic_read(&head) + bytes_to_copy) % BUFFER_CAPACITY);
    atomic_add(bytes_to_copy, &current_data_size);
}


// --- Driver Function Implementations (file_operations) ---

static int my_open(struct inode *inode, struct file *file) {
    printk(KERN_INFO "My Device: Opened device.\n");
    return 0;
}

static int my_release(struct inode *inode, struct file *file) {
    printk(KERN_INFO "My Device: Released device.\n");
    return 0;
}

static ssize_t my_read(struct file *file_pointer, char __user *user_space_buffer, size_t count, loff_t *offset) {
    ssize_t ret = 0;
    size_t bytes_to_read;

    printk(KERN_INFO "My Device: Read called. Current data size: %d, Task: %s\n", atomic_read(&current_data_size), current->comm);

    // If buffer is empty and O_NONBLOCK is NOT set, wait for data
    if (is_buffer_empty()) {
        if (file_pointer->f_flags & O_NONBLOCK) { // Check if non-blocking mode
            printk(KERN_INFO "My Device: Read - Buffer empty, non-blocking mode.\n");
            return -EAGAIN; // Resource temporarily unavailable
        }
        printk(KERN_INFO "My Device: Read - Buffer empty, waiting for data. Task: %s\n", current->comm);
        // Sleep until data is available or signal interrupts
        ret = wait_event_interruptible(read_queue, !is_buffer_empty());

        // Fix for format specifier warning: cast ret to int
        printk(KERN_INFO "My Device: Read - wait_event_interruptible returned %d. Current data size: %d\n", (int)ret, atomic_read(&current_data_size));

        if (ret == -ERESTARTSYS) { // Interrupted by a signal
            printk(KERN_INFO "My Device: Read - Interrupted by signal (-ERESTARTSYS). Returning -EINTR to user space.\n");
            return -EINTR; // <--- This is the crucial direct return of -EINTR
        } else if (ret < 0) { // Other unexpected errors from wait_event_interruptible
            // Fix for format specifier warning: cast ret to int
            printk(KERN_ERR "My Device: Read - wait_event_interruptible returned unexpected error %d.\n", (int)ret);
            return ret; // Return other errors directly
        }
        // If ret is 0, it means it woke up because condition !is_buffer_empty() is true.
    }

    // Determine how much data to copy
    bytes_to_read = min_t(size_t, count, atomic_read(&current_data_size));

    if (bytes_to_read == 0) {
        printk(KERN_INFO "My Device: Read - No bytes to read (buffer empty or count is 0). Current data size: %d.\n", atomic_read(&current_data_size));
        return 0; // No data to read even after waiting (e.g., if another reader took it)
    }

    // Read from circular buffer (handling wrap-around)
    size_t tail_val = atomic_read(&tail);
    size_t first_part = min_t(size_t, bytes_to_read, BUFFER_CAPACITY - tail_val); // Bytes till end of buffer
    size_t second_part = bytes_to_read - first_part; // Remaining bytes from beginning of buffer

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
    atomic_set(&tail, (tail_val + bytes_to_read) % BUFFER_CAPACITY);
    atomic_sub(bytes_to_read, &current_data_size);

    printk(KERN_INFO "My Device: Read %zu bytes. New data size: %d, New tail: %d.\n",
           bytes_to_read, atomic_read(&current_data_size), atomic_read(&tail));

    wake_up_interruptible(&write_queue); // Wake up any writers waiting for space
    return bytes_to_read;
}

static ssize_t my_write(struct file *file_pointer, const char __user *user_space_buffer, size_t count, loff_t *offset) {
    ssize_t ret = 0;
    char *temp_k_buf = NULL; // Temporary kernel buffer for copying from user

    printk(KERN_INFO "My Device: Write called. Current data size: %d, Task: %s\n", atomic_read(&current_data_size), current->comm);

    if (count == 0) return 0; // Nothing to write

    // If buffer is full and O_NONBLOCK is NOT set, wait for space
    if (is_buffer_full()) {
        if (file_pointer->f_flags & O_NONBLOCK) {
            printk(KERN_INFO "My Device: Write - Buffer full, non-blocking mode.\n");
            return -EAGAIN;
        }
        printk(KERN_INFO "My Device: Write - Buffer full, waiting for space...\n");
        ret = wait_event_interruptible(write_queue, !is_buffer_full()); // Wait for space
        if (ret == -ERESTARTSYS) {
            printk(KERN_INFO "My Device: Write - Interrupted by signal (-ERESTARTSYS). Returning -EINTR.\n");
            return -EINTR;
        } else if (ret < 0) {
            // Fix for format specifier warning: cast ret to int
            printk(KERN_ERR "My Device: Write - wait_event_interruptible returned unexpected error %d.\n", (int)ret);
            return ret;
        }
        // If ret is 0, it woke up because space is available.
    }

    // Determine how much data to copy
    size_t bytes_to_write = min_t(size_t, count, get_buffer_free_space());

    if (bytes_to_write == 0) {
        printk(KERN_WARNING "My Device: Write - No space to write after waiting. Current free: %zu.\n", get_buffer_free_space());
        return -ENOSPC; // No space left on device
    }

    // Allocate temporary kernel buffer for copying from user space
    temp_k_buf = kmalloc(bytes_to_write, GFP_KERNEL);
    if (!temp_k_buf) {
        printk(KERN_ERR "My Device: Error allocating temporary kernel buffer for write.\n");
        return -ENOMEM;
    }

    // Copy from user space to temporary kernel buffer
    if (copy_from_user(temp_k_buf, user_space_buffer, bytes_to_write)) {
        printk(KERN_ERR "My Device: Failed to copy data from user space (write).\n");
        kfree(temp_k_buf);
        return -EFAULT;
    }

    // Add data from temporary kernel buffer to circular buffer
    add_data_to_circular_buffer(temp_k_buf, bytes_to_write);

    printk(KERN_INFO "My Device: Wrote %zu bytes. New data size: %d, New head: %d.\n",
           bytes_to_write, atomic_read(&current_data_size), atomic_read(&head));

    wake_up_interruptible(&read_queue); // Wake up any sleeping readers!

    kfree(temp_k_buf); // Free the temporary buffer
    return bytes_to_write;
}


static long my_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    int retval = 0;
    // Removed 'user_val' as it's no longer used, fixing the warning.
    // int user_val = 0; // For arguments from user space

    printk(KERN_INFO "My Device: ioctl command received: 0x%x, Task: %s\n", cmd, current->comm);

    switch (cmd) {
        case MY_DEVICE_IOCTL_GET_STATUS:
            // Example: return current buffer_size as status
            retval = put_user(atomic_read(&current_data_size), (int __user *)arg);
            if (retval != 0) return -EFAULT;
            printk(KERN_INFO "My Device: GET_STATUS - returned buffer data size: %d.\n", atomic_read(&current_data_size));
            break;

        case MY_DEVICE_IOCTL_CLEAR_BUFFER:
            atomic_set(&head, 0);
            atomic_set(&tail, 0);
            atomic_set(&current_data_size, 0);
            memset(circular_buffer, 0, BUFFER_CAPACITY); // Clear content
            printk(KERN_INFO "My Device: RESET_BUFFER - buffer cleared and pointers reset.\n");
            wake_up_interruptible(&read_queue); // Notify readers that buffer is empty (if they were waiting for clear)
            wake_up_interruptible(&write_queue); // Notify writers that space is available
            break;

        default:
            printk(KERN_WARNING "My Device: Unknown ioctl command 0x%x.\n", cmd);
            return -ENOTTY; // Inappropriate ioctl for device
    }
    return 0; // Success
}

// --- file_operations structure ---
static const struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = my_open,
    .release = my_release,
    .read = my_read,
    .write = my_write,
    .unlocked_ioctl = my_ioctl,
};

// --- Module Initialization & Exit ---

static int __init my_module_init(void) {
    int ret;
    printk(KERN_INFO "My Device: Initializing character device module.\n");

    // 1. Allocate a major/minor number range
    ret = alloc_chrdev_region(&my_device_nbr, 0, 1, DEVICE_NAME); // Use DEVICE_NAME here
    if (ret < 0) {
        printk(KERN_ERR "My Device: Failed to allocate char dev region (%d).\n", ret);
        return ret;
    }
    printk(KERN_INFO "My Device: Allocated device number Major: %d Minor: %d\n", MAJOR(my_device_nbr), MINOR(my_device_nbr));

    // 2. Create a device class (will appear in /sys/class/)
    my_device_class = class_create(CLASS_NAME); // Use CLASS_NAME here
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
    my_device_device = device_create(my_device_class, NULL, my_device_nbr, NULL, DEVICE_NAME);
    if (IS_ERR(my_device_device)) {
        printk(KERN_ERR "My Device: Failed to create device.\n");
        cdev_del(&my_cdev);
        class_destroy(my_device_class);
        unregister_chrdev_region(my_device_nbr, 1);
        return PTR_ERR(my_device_device); // Return error pointer
    }
    printk(KERN_INFO "My Device: Device file created at /dev/%s\n", DEVICE_NAME);

    // Allocate circular buffer
    circular_buffer = kmalloc(BUFFER_CAPACITY, GFP_KERNEL);
    if (!circular_buffer) {
        printk(KERN_ERR "My Device: Error allocating memory for circular buffer.\n");
        // Cleanup on kmalloc failure
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
        add_data_to_circular_buffer(initial_msg, msg_len); // Use new helper function
        printk(KERN_INFO "My Device: Initial message added to buffer.\n");
    } else {
        printk(KERN_WARNING "My Device: Initial message too large for buffer.\n");
    }
    wake_up_interruptible(&read_queue); // Wake up any readers waiting for this initial message

    printk(KERN_INFO "My Device: Module loaded successfully.\n");
    return 0;
}

static void __exit my_module_exit(void) {
    printk(KERN_INFO "My Device: Exiting module.\n");

    // Ensure all resources are freed in reverse order of allocation
    if (my_device_device) {
        device_destroy(my_device_class, my_device_nbr);
    }
    cdev_del(&my_cdev); // Delete cdev
    if (my_device_class) {
        class_destroy(my_device_class);
    }
    unregister_chrdev_region(my_device_nbr, 1); // Unregister major/minor
    kfree(circular_buffer); // Free kmalloc'd memory

    printk(KERN_INFO "My Device: Module unloaded.\n");
}

module_init(my_module_init);
module_exit(my_module_exit);
