#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>       // For file_operations
#include <linux/cdev.h>     // For cdev_init, cdev_add
#include <linux/slab.h>     // For kmalloc, kfree
#include <linux/uaccess.h>  // For copy_to_user, copy_from_user
#include <linux/atomic.h>   // For atomic_t
#include <linux/wait.h>     // For wait_queue_head_t, wait_event_interruptible, wake_up_interruptible
#include <linux/errno.h>    // For EBUSY, ENOMEM, etc.
#include <linux/poll.h>     // For poll_table, poll_wait, POLLIN, POLLOUT
#include <linux/workqueue.h> // <--- NEW: For workqueues
#include <linux/jiffies.h>   // <--- NEW: For jiffies and time conversions (msecs_to_jiffies)
#include <linux/string.h>    // <--- NEW: For snprintf

// Include our custom ioctl header
#include "my_device_ioctl.h"

#define DEVICE_NAME "my_device"
#define DEFAULT_BUFFER_CAPACITY 256 // Initial default capacity
#define GENERATOR_INTERVAL_MS 1000 // <--- NEW: Data generation interval (1 second)

static dev_t my_device_nr;
static struct cdev my_cdev;

// --- Circular Buffer Global Variables ---
static char *circular_buffer;
static atomic_t head;                     // Write pointer
static atomic_t tail;                     // Read pointer
static atomic_t current_data_size;        // Current data in buffer
static unsigned int current_buffer_capacity; // Actual current capacity (dynamic)

// --- Wait Queues ---
static DECLARE_WAIT_QUEUE_HEAD(read_queue);
static DECLARE_WAIT_QUEUE_HEAD(write_queue);

// --- NEW: Workqueue related variables ---
static struct delayed_work my_generator_work;
static u64 data_packet_counter = 0; // Counter for generated data messages

// --- Helper Functions for Circular Buffer ---
bool is_buffer_empty(void) {
    return atomic_read(&current_data_size) == 0;
}

bool is_buffer_full(void) {
    return atomic_read(&current_data_size) == current_buffer_capacity;
}

unsigned int get_buffer_free_space(void) {
    return current_buffer_capacity - atomic_read(&current_data_size);
}

// Function to add data to the circular buffer (internal use)
// Assumes enough space is available. Caller should check!
static void add_data_to_circular_buffer(const char *data, size_t len) {
    unsigned int current_head = atomic_read(&head);
    unsigned int bytes_to_end = current_buffer_capacity - current_head;

    if (len <= bytes_to_end) {
        // Data fits without wrapping
        memcpy(circular_buffer + current_head, data, len);
    } else {
        // Data wraps around
        memcpy(circular_buffer + current_head, data, bytes_to_end);
        memcpy(circular_buffer, data + bytes_to_end, len - bytes_to_end);
    }

    atomic_set(&head, (current_head + len) % current_buffer_capacity);
    atomic_add(len, &current_data_size);
}

// --- NEW: Workqueue function for data generation ---
static void my_delayed_work_func(struct work_struct *work) {
    char data_to_add[64]; // Temporary buffer for generated data
    size_t len;
    unsigned int free_space = get_buffer_free_space();

    // Increment data counter
    data_packet_counter++;

    // Format the data string
    len = snprintf(data_to_add, sizeof(data_to_add),
                   "K-DATA: %llu @ %lu jiffies\n", data_packet_counter, jiffies);

    // Ensure the message length doesn't exceed the buffer size or our temp buffer
    if (len >= sizeof(data_to_add)) {
        // Truncation happened or message is too long, adjust length
        len = sizeof(data_to_add) - 1; // Null-terminate for safety
        data_to_add[len] = '\0';
    }

    // Check if there is enough space in the circular buffer
    if (free_space >= len) {
        add_data_to_circular_buffer(data_to_add, len);
        printk(KERN_INFO "My Device: Workqueue generated %zu bytes. Data size now %d.\n",
               len, atomic_read(&current_data_size));
        wake_up_interruptible(&read_queue); // Wake up any waiting readers or poll()
    } else {
        printk(KERN_WARNING "My Device: Workqueue: Not enough space to generate data (%zu bytes needed, %u available).\n",
               len, free_space);
    }

    // Reschedule the work for next interval
    schedule_delayed_work(&my_generator_work, msecs_to_jiffies(GENERATOR_INTERVAL_MS));
}

// --- Device File Operations (omitted unchanged functions for brevity) ---
// (my_open, my_release, my_read, my_write, my_ioctl, my_poll remain the same)
static int my_open(struct inode *inode, struct file *file_pointer) {
    printk(KERN_INFO "My Device: Device opened.\n");
    return 0;
}

static int my_release(struct inode *inode, struct file *file_pointer) {
    printk(KERN_INFO "My Device: Device closed.\n");
    return 0;
}

static ssize_t my_read(struct file *file_pointer, char __user *buffer, size_t count, loff_t *offset) {
    ssize_t bytes_read = 0;
    unsigned int current_tail;
    unsigned int bytes_available;
    int ret;

    printk(KERN_INFO "My Device: Read called (requested %zu bytes).\n", count);

    // Wait for data if buffer is empty
    if (is_buffer_empty()) {
        if (file_pointer->f_flags & O_NONBLOCK) {
            printk(KERN_INFO "My Device: Read - Buffer empty, non-blocking.\n");
            return -EAGAIN; // Resource temporarily unavailable
        }
        printk(KERN_INFO "My Device: Read - Buffer empty, waiting for data...\n");
        ret = wait_event_interruptible(read_queue, !is_buffer_empty() || !current_buffer_capacity); // Also wake if capacity goes to 0
        if (ret == -ERESTARTSYS) { // Interrupted by a signal
            printk(KERN_WARNING "My Device: Read - Interrupted by signal.\n");
            return -EINTR; // Return -EINTR to user-space
        } else if (ret < 0) { // Other wait errors
            printk(KERN_ERR "My Device: Read - Wait event error: %d\n", (int)ret);
            return ret;
        }
        // Check if woke up due to buffer empty but capacity became 0 (module being unloaded?)
        if (is_buffer_empty() && current_buffer_capacity == 0) {
            printk(KERN_WARNING "My Device: Read - Woke up but buffer is empty and capacity is 0. Exiting read.\n");
            return 0; // Or -EIO if it's an error condition
        }
    }

    current_tail = atomic_read(&tail);
    bytes_available = atomic_read(&current_data_size);
    bytes_read = min((size_t)bytes_available, count); // Read up to available data or requested count

    // Handle circular wrap-around
    unsigned int bytes_to_end = current_buffer_capacity - current_tail;
    if (bytes_read <= bytes_to_end) {
        // Data fits without wrapping
        if (copy_to_user(buffer, circular_buffer + current_tail, bytes_read)) {
            printk(KERN_ERR "My Device: Failed to copy data to user space (read).\n");
            return -EFAULT;
        }
    } else {
        // Data wraps around: copy till end, then copy from beginning
        if (copy_to_user(buffer, circular_buffer + current_tail, bytes_to_end)) {
            printk(KERN_ERR "My Device: Failed to copy data to user space (read - part 1).\n");
            return -EFAULT;
        }
        if (copy_to_user(buffer + bytes_to_end, circular_buffer, bytes_read - bytes_to_end)) {
            printk(KERN_ERR "My Device: Failed to copy data to user space (read - part 2).\n");
            return -EFAULT;
        }
    }

    atomic_set(&tail, (current_tail + bytes_read) % current_buffer_capacity);
    atomic_sub(bytes_read, &current_data_size);

    printk(KERN_INFO "My Device: Read %zd bytes. Data size now %d. Free space %u.\n",
           bytes_read, atomic_read(&current_data_size), get_buffer_free_space());

    wake_up_interruptible(&write_queue); // Wake up any waiting writers as space is available
    return bytes_read;
}

static ssize_t my_write(struct file *file_pointer, const char __user *buffer, size_t count, loff_t *offset) {
    ssize_t bytes_written = 0;
    char *temp_k_buf;
    unsigned int free_space;
    int ret;

    printk(KERN_INFO "My Device: Write called (requested %zu bytes).\n", count);

    // Allocate a temporary kernel buffer to copy user data first
    temp_k_buf = kmalloc(count, GFP_KERNEL);
    if (!temp_k_buf) {
        printk(KERN_ERR "My Device: Failed to allocate temporary kernel buffer for write.\n");
        return -ENOMEM;
    }

    if (copy_from_user(temp_k_buf, buffer, count)) {
        printk(KERN_ERR "My Device: Failed to copy data from user space (write).\n");
        kfree(temp_k_buf);
        return -EFAULT;
    }

    // Wait for space if buffer is full
    if (is_buffer_full()) {
        if (file_pointer->f_flags & O_NONBLOCK) {
            printk(KERN_INFO "My Device: Write - Buffer full, non-blocking.\n");
            kfree(temp_k_buf);
            return -EAGAIN;
        }
        printk(KERN_INFO "My Device: Write - Buffer full, waiting for space...\n");
        ret = wait_event_interruptible(write_queue, !is_buffer_full() || !current_buffer_capacity); // Also wake if capacity goes to 0
        if (ret == -ERESTARTSYS) {
            printk(KERN_WARNING "My Device: Write - Interrupted by signal.\n");
            kfree(temp_k_buf);
            return -EINTR;
        } else if (ret < 0) {
            printk(KERN_ERR "My Device: Write - Wait event error: %d\n", (int)ret);
            kfree(temp_k_buf);
            return ret;
        }
        // Check if woke up due to buffer full but capacity became 0
        if (is_buffer_full() && current_buffer_capacity == 0) {
             printk(KERN_WARNING "My Device: Write - Woke up but buffer is full and capacity is 0. Exiting write.\n");
             kfree(temp_k_buf);
             return -ENOSPC; // No space left on device
        }
    }

    free_space = get_buffer_free_space();
    bytes_written = min((size_t)free_space, count); // Write up to available space or requested count

    // Add data to circular buffer
    add_data_to_circular_buffer(temp_k_buf, bytes_written);

    printk(KERN_INFO "My Device: Wrote %zd bytes. Data size now %d. Free space %u.\n",
           bytes_written, atomic_read(&current_data_size), get_buffer_free_space());

    kfree(temp_k_buf); // Free temporary buffer
    wake_up_interruptible(&read_queue); // Wake up any waiting readers as data is available
    return bytes_written;
}


static long my_ioctl(struct file *file_pointer, unsigned int cmd, unsigned long arg) {
    int ret = 0;
    my_device_status_t status;
    int new_capacity_req;
    unsigned int old_capacity;
    char *new_circular_buffer;

    printk(KERN_INFO "My Device: ioctl command received: 0x%x\n", cmd);

    switch (cmd) {
        case MY_DEVICE_IOCTL_GET_STATUS:
            status.current_data_size = atomic_read(&current_data_size);
            status.buffer_capacity = current_buffer_capacity;
            if (copy_to_user((my_device_status_t __user *)arg, &status, sizeof(my_device_status_t))) {
                printk(KERN_ERR "My Device: Failed to copy status to user space.\n");
                ret = -EFAULT;
            }
            break;

        case MY_DEVICE_IOCTL_CLEAR_BUFFER:
            atomic_set(&head, 0);
            atomic_set(&tail, 0);
            atomic_set(&current_data_size, 0);
            memset(circular_buffer, 0, current_buffer_capacity); // Clear contents
            printk(KERN_INFO "My Device: RESET_BUFFER - buffer cleared, head/tail/size reset.\n");
            wake_up_interruptible(&read_queue);  // Wake readers (buffer is empty)
            wake_up_interruptible(&write_queue); // Wake writers (buffer is full of free space)
            break;

        case MY_DEVICE_IOCTL_SET_CAPACITY:
            if (copy_from_user(&new_capacity_req, (int __user *)arg, sizeof(int))) {
                printk(KERN_ERR "My Device: Failed to copy new capacity from user space.\n");
                ret = -EFAULT;
                break;
            }

            if (new_capacity_req <= 0 || new_capacity_req > (1024 * 1024)) { // Max 1MB for safety
                printk(KERN_WARNING "My Device: Invalid requested capacity %d. Must be > 0 and <= 1MB.\n", new_capacity_req);
                ret = -EINVAL; // Invalid argument
                break;
            }

            if (new_capacity_req == current_buffer_capacity) {
                printk(KERN_INFO "My Device: Requested capacity is same as current (%d). No change.\n", new_capacity_req);
                break; // No change needed
            }

            // Important: Only reallocate if buffer is empty to avoid data loss complexity
            if (atomic_read(&current_data_size) > 0) {
                printk(KERN_WARNING "My Device: Cannot change capacity. Buffer contains data (%d bytes). Please clear first.\n",
                       atomic_read(&current_data_size));
                ret = -EBUSY; // Device or resource busy
                break;
            }

            // Perform reallocation
            old_capacity = current_buffer_capacity;
            new_circular_buffer = kmalloc(new_capacity_req, GFP_KERNEL);
            if (!new_circular_buffer) {
                printk(KERN_ERR "My Device: Failed to allocate new buffer of size %d. Retaining old capacity %u.\n",
                       new_capacity_req, old_capacity);
                ret = -ENOMEM; // Out of memory
                break;
            }

            // Free old buffer and update pointers
            kfree(circular_buffer);
            circular_buffer = new_circular_buffer;
            current_buffer_capacity = new_capacity_req;
            memset(circular_buffer, 0, current_buffer_capacity); // Zero out new buffer

            // Reset pointers after reallocation
            atomic_set(&head, 0);
            atomic_set(&tail, 0);
            atomic_set(&current_data_size, 0);

            printk(KERN_INFO "My Device: Buffer capacity changed from %u to %u.\n", old_capacity, current_buffer_capacity);
            wake_up_interruptible(&read_queue);  // New state might affect sleepers
            wake_up_interruptible(&write_queue);
            break;

        default:
            printk(KERN_WARNING "My Device: Unknown ioctl command 0x%x\n", cmd);
            ret = -ENOTTY; // Inappropriate ioctl for device
            break;
    }
    return ret;
}

static __poll_t my_poll(struct file *file, poll_table *wait) {
    __poll_t mask = 0;

    poll_wait(file, &read_queue, wait);
    poll_wait(file, &write_queue, wait);

    if (!is_buffer_empty()) {
        mask |= POLLIN | POLLRDNORM;
    }

    if (!is_buffer_full()) {
        mask |= POLLOUT | POLLWRNORM;
    }

    printk(KERN_DEBUG "My Device: poll called, returning mask 0x%x (POLLIN: %d, POLLOUT: %d)\n", mask, (mask & POLLIN) ? 1 : 0, (mask & POLLOUT) ? 1 : 0);
    return mask;
}


static const struct file_operations my_fops = {
    .owner   = THIS_MODULE,
    .open    = my_open,
    .release = my_release,
    .read    = my_read,
    .write   = my_write,
    .unlocked_ioctl = my_ioctl,
    .poll    = my_poll,
};

// --- Module Initialization and Exit ---

static int __init my_module_init(void) {
    int ret;

    // Allocate device number dynamically
    ret = alloc_chrdev_region(&my_device_nr, 0, 1, DEVICE_NAME);
    if (ret < 0) {
        printk(KERN_ERR "My Device: Failed to allocate device number.\n");
        return ret;
    }
    printk(KERN_INFO "My Device: Allocated device number: %d:%d\n", MAJOR(my_device_nr), MINOR(my_device_nr));

    // Initialize cdev structure
    cdev_init(&my_cdev, &my_fops);
    my_cdev.owner = THIS_MODULE;

    // Add cdev to the system
    ret = cdev_add(&my_cdev, my_device_nr, 1);
    if (ret < 0) {
        printk(KERN_ERR "My Device: Failed to add cdev.\n");
        unregister_chrdev_region(my_device_nr, 1);
        return ret;
    }

    // Initialize circular buffer with default capacity
    current_buffer_capacity = DEFAULT_BUFFER_CAPACITY;
    circular_buffer = kmalloc(current_buffer_capacity, GFP_KERNEL);
    if (!circular_buffer) {
        printk(KERN_ERR "My Device: Failed to allocate circular buffer memory.\n");
        cdev_del(&my_cdev);
        unregister_chrdev_region(my_device_nr, 1);
        return -ENOMEM;
    }
    memset(circular_buffer, 0, current_buffer_capacity);

    // Initialize buffer pointers
    atomic_set(&head, 0);
    atomic_set(&tail, 0);
    atomic_set(&current_data_size, 0);

    printk(KERN_INFO "My Device: Kernel Circular Buffer Ready! Capacity: %u bytes.\n", current_buffer_capacity);

    // Add an initial message to the buffer (for immediate read test)
    const char *initial_msg = "Kernel Circular Buffer Ready!\n";
    size_t msg_len = strlen(initial_msg);
    if (msg_len <= current_buffer_capacity) {
        add_data_to_circular_buffer(initial_msg, msg_len);
        printk(KERN_INFO "My Device: Initial message added to buffer. Size: %d\n", atomic_read(&current_data_size));
        wake_up_interruptible(&read_queue); // Wake up any potential readers
    } else {
        printk(KERN_WARNING "My Device: Initial message too large for default buffer capacity.\n");
    }

    // <--- NEW: Initialize and schedule the delayed work
    INIT_DELAYED_WORK(&my_generator_work, my_delayed_work_func);
    schedule_delayed_work(&my_generator_work, msecs_to_jiffies(GENERATOR_INTERVAL_MS));
    printk(KERN_INFO "My Device: Data generator workqueue scheduled to run every %d ms.\n", GENERATOR_INTERVAL_MS);


    printk(KERN_INFO "My Device: Module loaded successfully.\n");
    return 0;
}

static void __exit my_module_exit(void) {
    // <--- NEW: Cancel the pending work before exiting
    // This is crucial to prevent kernel warnings/crashes if the workqueue tries to run after module is unloaded.
    cancel_delayed_work_sync(&my_generator_work);
    printk(KERN_INFO "My Device: Data generator workqueue cancelled.\n");


    if (circular_buffer) {
        current_buffer_capacity = 0; // Signal that buffer is gone
        wake_up_interruptible(&read_queue);
        wake_up_interruptible(&write_queue);
        kfree(circular_buffer);
        circular_buffer = NULL;
    }
    cdev_del(&my_cdev);
    unregister_chrdev_region(my_device_nr, 1);
    printk(KERN_INFO "My Device: Module unloaded.\n");
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ayush Ranjan");
MODULE_DESCRIPTION("A simple character device driver with circular buffer, blocking I/O, dynamic capacity, polling, and a kernel data generator.");
MODULE_VERSION("1.3");
