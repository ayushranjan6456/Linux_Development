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
#include <linux/workqueue.h> // For workqueues
#include <linux/jiffies.h>   // For jiffies and time conversions (msecs_to_jiffies)
#include <linux/string.h>    // For snprintf, memset, memcpy
#include <linux/mutex.h>    // For mutexes
#include <linux/device.h>   // For class_create, device_create (for udev)

// Include our custom ioctl header
#include "my_device_ioctl.h"

#define DEVICE_NAME "my_device_node" // Changed to match user app's expectation
#define DEFAULT_BUFFER_CAPACITY 256 // Initial default capacity
#define GENERATOR_INTERVAL_MS 1000 // Data generation interval (1 second)
#define MAX_BUFFER_CAPACITY (4 * PAGE_SIZE) // Define a max capacity for safety, e.g., 4 pages

static dev_t my_device_nr;
static struct cdev my_cdev;
static struct class *my_device_class; // Device class for udev integration

// --- Circular Buffer Global Variables ---
static char *circular_buffer;
static unsigned int head_ptr;                     // Write pointer (protected by mutex)
static unsigned int tail_ptr;                     // Read pointer (protected by mutex)
static unsigned int current_data_size;        // Current data in buffer (protected by mutex)
static unsigned int current_buffer_capacity; // Actual current capacity (dynamic)

// --- Wait Queues ---
static DECLARE_WAIT_QUEUE_HEAD(read_queue);
static DECLARE_WAIT_QUEUE_HEAD(write_queue);

// --- Mutex for protecting the circular buffer and its state ---
static DEFINE_MUTEX(my_device_mutex);

// --- Workqueue related variables ---
static struct delayed_work my_generator_work;
static u64 data_packet_counter = 0; // Counter for generated data messages

// --- Helper Functions for Circular Buffer ---
// These functions now assume the caller holds the mutex.
static bool is_buffer_empty(void) {
    return current_data_size == 0;
}

static bool is_buffer_full(void) {
    return current_data_size == current_buffer_capacity;
}

static unsigned int get_buffer_free_space(void) {
    return current_buffer_capacity - current_data_size;
}

// Function to add data to the circular buffer (internal use)
// Assumes enough space is available. Caller should check!
// IMPORTANT: This function now expects the mutex to be held by the caller.
static void add_data_to_circular_buffer(const char *data, size_t len) {
    // Mutex should be held here by the caller (my_delayed_work_func or my_write)
    unsigned int current_head = head_ptr;
    unsigned int bytes_to_end = current_buffer_capacity - current_head;

    if (len <= bytes_to_end) {
        // Data fits without wrapping
        memcpy(circular_buffer + current_head, data, len);
    } else {
        // Data wraps around
        memcpy(circular_buffer + current_head, data, bytes_to_end);
        memcpy(circular_buffer, data + bytes_to_end, len - bytes_to_end);
    }

    head_ptr = (current_head + len) % current_buffer_capacity;
    current_data_size += len;
}

// --- Workqueue function for data generation ---
static void my_delayed_work_func(struct work_struct *work) {
    char data_to_add[64]; // Temporary buffer for generated data
    size_t len;

    mutex_lock(&my_device_mutex); // Acquire mutex before accessing shared buffer

    if (current_buffer_capacity == 0 || !circular_buffer) {
        printk(KERN_WARNING "My Device: Generator: Buffer not initialized or capacity is zero. Not generating data.\n");
        goto unlock_and_reschedule;
    }

    if (is_buffer_full()) {
        printk(KERN_INFO "My Device: Generator: Buffer full. Not generating data.\n");
        goto unlock_and_reschedule;
    }

    // Increment data counter
    data_packet_counter++;

    // Format the data string
    len = snprintf(data_to_add, sizeof(data_to_add),
                   "K-DATA: %llu @ %lu jiffies\n", data_packet_counter, jiffies);

    // Ensure the message length doesn't exceed the buffer size or our temp buffer
    if (len >= sizeof(data_to_add)) {
        len = sizeof(data_to_add) - 1; // Null-terminate for safety
        data_to_add[len] = '\0';
    }

    // Check if there is enough space in the circular buffer
    unsigned int free_space = get_buffer_free_space();
    if (free_space >= len) {
        add_data_to_circular_buffer(data_to_add, len);
        printk(KERN_INFO "My Device: Workqueue generated %zu bytes. Data size now %u.\n",
               len, current_data_size);
        wake_up_interruptible(&read_queue); // Wake up any waiting readers or poll()
    } else {
        printk(KERN_WARNING "My Device: Workqueue: Not enough space to generate data (%zu bytes needed, %u available).\n",
               len, free_space);
    }

unlock_and_reschedule:
    mutex_unlock(&my_device_mutex); // Release mutex

    // Reschedule the work for next interval
    schedule_delayed_work(&my_generator_work, msecs_to_jiffies(GENERATOR_INTERVAL_MS));
}

// --- Device File Operations ---
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
    int ret;

    // Acquire mutex before starting read operation
    if (!mutex_trylock(&my_device_mutex)) {
        if (file_pointer->f_flags & O_NONBLOCK) {
            printk(KERN_DEBUG "My Device: Read called in non-blocking mode, mutex busy. Returning EAGAIN.\n");
            return -EAGAIN;
        }
        mutex_lock(&my_device_mutex); // Blocking acquire
    }

    printk(KERN_INFO "My Device: Read called (requested %zu bytes).\n", count);

    // Wait for data if buffer is empty
    while (is_buffer_empty()) { // is_buffer_empty checks current_data_size, which is mutex-protected.
        mutex_unlock(&my_device_mutex); // Release mutex before waiting

        if (file_pointer->f_flags & O_NONBLOCK) {
            printk(KERN_INFO "My Device: Read - Buffer empty, non-blocking.\n");
            return -EAGAIN;
        }
        printk(KERN_INFO "My Device: Read - Buffer empty, waiting for data...\n");

        ret = wait_event_interruptible(read_queue, !is_buffer_empty() || current_buffer_capacity == 0); // Wake also if capacity goes to 0 (module exit)
        if (ret == -ERESTARTSYS) { // Interrupted by a signal
            printk(KERN_WARNING "My Device: Read - Interrupted by signal.\n");
            return -EINTR; // Return -EINTR to user-space
        } else if (ret < 0) { // Other wait errors
            printk(KERN_ERR "My Device: Read - Wait event error: %d\n", (int)ret);
            return ret;
        }
        // Re-acquire mutex after waking up
        mutex_lock(&my_device_mutex);

        // Check if woke up due to buffer empty but capacity became 0 (module being unloaded?)
        if (is_buffer_empty() && current_buffer_capacity == 0) {
            printk(KERN_WARNING "My Device: Read - Woke up but buffer is empty and capacity is 0. Exiting read.\n");
            bytes_read = 0; // Return 0 bytes on device shutdown
            goto out;
        }
    }

    // Determine how many bytes to actually read
    bytes_read = min((size_t)current_data_size, count); // Read up to available data or requested count

    // Handle circular wrap-around
    unsigned int bytes_to_end = current_buffer_capacity - tail_ptr;
    if (bytes_read <= bytes_to_end) {
        // Data fits without wrapping
        if (copy_to_user(buffer, circular_buffer + tail_ptr, bytes_read)) {
            printk(KERN_ERR "My Device: Failed to copy data to user space (read).\n");
            bytes_read = -EFAULT;
            goto out;
        }
    } else {
        // Data wraps around: copy till end, then copy from beginning
        if (copy_to_user(buffer, circular_buffer + tail_ptr, bytes_to_end)) {
            printk(KERN_ERR "My Device: Failed to copy data to user space (read - part 1).\n");
            bytes_read = -EFAULT;
            goto out;
        }
        if (copy_to_user(buffer + bytes_to_end, circular_buffer, bytes_read - bytes_to_end)) {
            printk(KERN_ERR "My Device: Failed to copy data to user space (read - part 2).\n");
            bytes_read = -EFAULT;
            goto out;
        }
    }

    tail_ptr = (tail_ptr + bytes_read) % current_buffer_capacity;
    current_data_size -= bytes_read;

    printk(KERN_INFO "My Device: Read %zd bytes. Data size now %u. Free space %u.\n",
           bytes_read, current_data_size, get_buffer_free_space());

    wake_up_interruptible(&write_queue); // Wake up any waiting writers as space is available

out:
    mutex_unlock(&my_device_mutex); // Release mutex before returning
    return bytes_read;
}

static ssize_t my_write(struct file *file_pointer, const char __user *buffer, size_t count, loff_t *offset) {
    ssize_t bytes_written = 0;
    char *temp_k_buf;
    int ret;

    // Acquire mutex before starting write operation
    if (!mutex_trylock(&my_device_mutex)) {
        if (file_pointer->f_flags & O_NONBLOCK) {
            printk(KERN_DEBUG "My Device: Write called in non-blocking mode, mutex busy. Returning EAGAIN.\n");
            return -EAGAIN;
        }
        mutex_lock(&my_device_mutex); // Blocking acquire
    }

    printk(KERN_INFO "My Device: Write called (requested %zu bytes).\n", count);

    // Allocate a temporary kernel buffer to copy user data first
    // This is done while holding the mutex to protect buffer_capacity
    temp_k_buf = kmalloc(count, GFP_KERNEL);
    if (!temp_k_buf) {
        printk(KERN_ERR "My Device: Failed to allocate temporary kernel buffer for write.\n");
        bytes_written = -ENOMEM;
        goto out;
    }

    if (copy_from_user(temp_k_buf, buffer, count)) {
        printk(KERN_ERR "My Device: Failed to copy data from user space (write).\n");
        bytes_written = -EFAULT;
        kfree(temp_k_buf); // Ensure temp buffer is freed on copy error
        goto out;
    }

    // Wait for space if buffer is full
    while (is_buffer_full()) { // is_buffer_full checks current_data_size, which is mutex-protected.
        mutex_unlock(&my_device_mutex); // Release mutex before waiting

        if (file_pointer->f_flags & O_NONBLOCK) {
            printk(KERN_INFO "My Device: Write - Buffer full, non-blocking.\n");
            bytes_written = -EAGAIN;
            kfree(temp_k_buf); // Free temp buffer on non-blocking exit
            return -EAGAIN;
        }
        printk(KERN_INFO "My Device: Write - Buffer full, waiting for space...\n");

        ret = wait_event_interruptible(write_queue, !is_buffer_full() || current_buffer_capacity == 0); // Wake also if capacity goes to 0
        if (ret == -ERESTARTSYS) {
            printk(KERN_WARNING "My Device: Write - Interrupted by signal.\n");
            bytes_written = -EINTR;
            kfree(temp_k_buf); // Free temp buffer on signal
            return -EINTR;
        } else if (ret < 0) {
            printk(KERN_ERR "My Device: Write - Wait event error: %d\n", (int)ret);
            bytes_written = ret;
            kfree(temp_k_buf);
            return ret;
        }
        // Re-acquire mutex after waking up
        mutex_lock(&my_device_mutex);

        // Check if woke up due to buffer full but capacity became 0
        if (is_buffer_full() && current_buffer_capacity == 0) {
             printk(KERN_WARNING "My Device: Write - Woke up but buffer is full and capacity is 0. Exiting write.\n");
             bytes_written = -ENOSPC; // No space left on device
             kfree(temp_k_buf);
             goto out;
        }
    }

    unsigned int free_space = get_buffer_free_space();
    bytes_written = min((size_t)free_space, count); // Write up to available space or requested count

    // Add data to circular buffer
    add_data_to_circular_buffer(temp_k_buf, bytes_written);

    printk(KERN_INFO "My Device: Wrote %zd bytes. Data size now %u. Free space %u.\n",
           bytes_written, current_data_size, get_buffer_free_space());

    kfree(temp_k_buf); // Free temporary buffer
    wake_up_interruptible(&read_queue); // Wake up any waiting readers as data is available

out:
    mutex_unlock(&my_device_mutex); // Release mutex before returning
    return bytes_written;
}


static long my_ioctl(struct file *file_pointer, unsigned int cmd, unsigned long arg) {
    long ret = 0;
    my_device_status_t status;
    int new_capacity_req;
    unsigned int old_capacity;
    char *new_circular_buffer;

    mutex_lock(&my_device_mutex); // IOCTL operations also need mutex protection

    printk(KERN_INFO "My Device: ioctl command received: 0x%x\n", cmd);

    switch (cmd) {
        case MY_DEVICE_IOCTL_GET_STATUS:
            status.current_data_size = current_data_size; // Now directly from mutex-protected variable
            status.buffer_capacity = current_buffer_capacity;
            if (copy_to_user((my_device_status_t __user *)arg, &status, sizeof(my_device_status_t))) {
                printk(KERN_ERR "My Device: Failed to copy status to user space.\n");
                ret = -EFAULT;
            }
            break;

        case MY_DEVICE_IOCTL_CLEAR_BUFFER:
            head_ptr = 0;
            tail_ptr = 0;
            current_data_size = 0;
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

            if (new_capacity_req <= 0 || new_capacity_req > (int)MAX_BUFFER_CAPACITY) { // <--- FIXED: Cast MAX_BUFFER_CAPACITY
                printk(KERN_WARNING "My Device: Invalid requested capacity %d. Must be > 0 and <= %u.\n",
                       new_capacity_req, (unsigned int)MAX_BUFFER_CAPACITY); // <--- FIXED: Cast MAX_BUFFER_CAPACITY
                ret = -EINVAL; // Invalid argument
                break;
            }

            if (new_capacity_req == (int)current_buffer_capacity) {
                printk(KERN_INFO "My Device: Requested capacity is same as current (%d). No change.\n", new_capacity_req);
                break; // No change needed
            }

            // Important: Only reallocate if buffer is empty to avoid data loss complexity
            if (current_data_size > 0) { // Using mutex-protected current_data_size
                printk(KERN_WARNING "My Device: Cannot change capacity. Buffer contains data (%u bytes). Please clear first.\n",
                       current_data_size);
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
            head_ptr = 0;
            tail_ptr = 0;
            current_data_size = 0;

            printk(KERN_INFO "My Device: Buffer capacity changed from %u to %u.\n", old_capacity, current_buffer_capacity);
            wake_up_interruptible(&read_queue);  // New state might affect sleepers
            wake_up_interruptible(&write_queue);
            break;

        default:
            printk(KERN_WARNING "My Device: Unknown ioctl command 0x%x\n", cmd);
            ret = -ENOTTY; // Inappropriate ioctl for device
            break;
    }
    mutex_unlock(&my_device_mutex); // Release mutex before returning
    return ret;
}

static __poll_t my_poll(struct file *file, poll_table *wait) {
    __poll_t mask = 0;

    mutex_lock(&my_device_mutex); // Acquire mutex for poll check

    poll_wait(file, &read_queue, wait);
    poll_wait(file, &write_queue, wait);

    if (!is_buffer_empty()) {
        mask |= POLLIN | POLLRDNORM;
    }

    if (!is_buffer_full()) {
        mask |= POLLOUT | POLLWRNORM;
    }

    printk(KERN_DEBUG "My Device: poll called, returning mask 0x%x (POLLIN: %d, POLLOUT: %d)\n", mask, (mask & POLLIN) ? 1 : 0, (mask & POLLOUT) ? 1 : 0);

    mutex_unlock(&my_device_mutex); // Release mutex
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
    int ret_val; // Renamed to avoid confusion with device_create's return type
    struct device *my_device_ptr; // <--- FIXED: Correct type for device_create return

    printk(KERN_INFO "My Device: Module loading...\n");

    // Allocate device number dynamically
    ret_val = alloc_chrdev_region(&my_device_nr, 0, 1, DEVICE_NAME);
    if (ret_val < 0) {
        printk(KERN_ERR "My Device: Failed to allocate device number.\n");
        return ret_val;
    }
    printk(KERN_INFO "My Device: Allocated device number: %d:%d\n", MAJOR(my_device_nr), MINOR(my_device_nr));

    // Create a device class for udev to automatically create /dev/my_device_node
    my_device_class = class_create(DEVICE_NAME);
    if (IS_ERR(my_device_class)) {
        printk(KERN_ERR "My Device: Failed to create device class.\n");
        unregister_chrdev_region(my_device_nr, 1);
        return PTR_ERR(my_device_class);
    }
    printk(KERN_INFO "My Device: Device class created: /sys/class/%s\n", DEVICE_NAME);

    // Create a device node using the device class
    my_device_ptr = device_create(my_device_class, NULL, my_device_nr, NULL, DEVICE_NAME); // <--- FIXED: Assign to struct device *
    if (IS_ERR(my_device_ptr)) { // <--- FIXED: Check the device pointer
        printk(KERN_ERR "My Device: Failed to create device node.\n");
        class_destroy(my_device_class); // Clean up class if device creation fails
        unregister_chrdev_region(my_device_nr, 1);
        return PTR_ERR(my_device_ptr); // <--- FIXED: Return error from the device pointer
    }
    printk(KERN_INFO "My Device: Device node will be created by udev at /dev/%s\n", DEVICE_NAME);

    // Initialize cdev structure
    cdev_init(&my_cdev, &my_fops);
    my_cdev.owner = THIS_MODULE;

    // Add cdev to the system
    ret_val = cdev_add(&my_cdev, my_device_nr, 1);
    if (ret_val < 0) {
        printk(KERN_ERR "My Device: Failed to add cdev.\n");
        // Use device_destroy with the class and dev_t, not the device pointer.
        device_destroy(my_device_class, my_device_nr); // Clean up device node
        class_destroy(my_device_class); // Clean up class
        unregister_chrdev_region(my_device_nr, 1);
        return ret_val;
    }

    // Initialize circular buffer with default capacity
    current_buffer_capacity = DEFAULT_BUFFER_CAPACITY;
    circular_buffer = kmalloc(current_buffer_capacity, GFP_KERNEL);
    if (!circular_buffer) {
        printk(KERN_ERR "My Device: Failed to allocate circular buffer memory.\n");
        cdev_del(&my_cdev);
        device_destroy(my_device_class, my_device_nr);
        class_destroy(my_device_class);
        unregister_chrdev_region(my_device_nr, 1);
        return -ENOMEM;
    }
    // Initialize pointers/size and clear buffer contents
    head_ptr = 0;
    tail_ptr = 0;
    current_data_size = 0;
    memset(circular_buffer, 0, current_buffer_capacity);


    printk(KERN_INFO "My Device: Kernel Circular Buffer Ready! Capacity: %u bytes.\n", current_buffer_capacity);

    // Add an initial message to the buffer (for immediate read test)
    mutex_lock(&my_device_mutex);
    const char *initial_msg = "Kernel Circular Buffer Ready!\n";
    size_t msg_len = strlen(initial_msg);
    if (msg_len <= current_buffer_capacity) {
        add_data_to_circular_buffer(initial_msg, msg_len);
        printk(KERN_INFO "My Device: Initial message added to buffer. Size: %u\n", current_data_size);
        wake_up_interruptible(&read_queue); // Wake up any potential readers
    } else {
        printk(KERN_WARNING "My Device: Initial message too large for default buffer capacity.\n");
    }
    mutex_unlock(&my_device_mutex);


    // Initialize and schedule the delayed work
    INIT_DELAYED_WORK(&my_generator_work, my_delayed_work_func);
    schedule_delayed_work(&my_generator_work, msecs_to_jiffies(GENERATOR_INTERVAL_MS));
    printk(KERN_INFO "My Device: Data generator workqueue scheduled to run every %d ms.\n", GENERATOR_INTERVAL_MS);


    printk(KERN_INFO "My Device: Module loaded successfully.\n");
    return 0;
}

static void __exit my_module_exit(void) {
    printk(KERN_INFO "My Device: Module unloading...\n");

    // Cancel the pending work before exiting
    cancel_delayed_work_sync(&my_generator_work);
    printk(KERN_INFO "My Device: Data generator workqueue cancelled.\n");

    // Free the circular buffer and wake up any waiting processes
    // This is done while holding the mutex to prevent races during shutdown
    mutex_lock(&my_device_mutex);
    if (circular_buffer) {
        current_buffer_capacity = 0; // Signal that buffer is gone
        kfree(circular_buffer);
        circular_buffer = NULL;
    }
    mutex_unlock(&my_device_mutex);

    // Wake up any waiting processes in case they're still in wait_event
    // They will check current_buffer_capacity == 0 and exit gracefully.
    wake_up_interruptible(&read_queue);
    wake_up_interruptible(&write_queue);

    cdev_del(&my_cdev);
    printk(KERN_INFO "My Device: cdev deleted.\n");

    // Destroy device node and class
    device_destroy(my_device_class, my_device_nr);
    printk(KERN_INFO "My Device: Device node destroyed.\n");
    class_destroy(my_device_class);
    printk(KERN_INFO "My Device: Device class destroyed.\n");

    unregister_chrdev_region(my_device_nr, 1);
    printk(KERN_INFO "My Device: Device number unregistered.\n");

    printk(KERN_INFO "My Device: Module unloaded.\n");
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ayush Ranjan");
MODULE_DESCRIPTION("An enhanced character device driver with circular buffer, blocking I/O, dynamic capacity, polling, and a kernel data generator.");
MODULE_VERSION("1.4");
