#include<linux/init.h>
#include<linux/module.h>
#include<linux/proc_fs.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ayush Ranjan");
MODULE_DESCRIPTION("A simple dynamically loadable kernel module");

static ssize_t ayush_read(struct file *file, 
                            char __user *buf, 
                            size_t count,
                            loff_t *offset);
                            
static ssize_t ayush_write(struct file *file,
                            const char __user *buf, 
                            size_t count,
                            loff_t *offset);

struct proc_ops driver_proc_ops = {
    .proc_open = NULL,
    .proc_read = ayush_read,
    .proc_write = ayush_write,
    .proc_lseek = NULL,
    .proc_release = NULL,
};
struct proc_dir_entry *custom_proc_entry;

static char *kernel_buffer;
static ssize_t buffer_size = 0;
#define BUFFER_SIZE 1024

static ssize_t ayush_read(struct file *file_pointer, 
                            char __user *user_space_buffer, 
                            size_t count,
                            loff_t *offset){
    if(*offset >= buffer_size){
        return 0;
    }

    printk("READ FUNCTION CALLED");

    printk("Count %ld, Offset %lld, Buffer Size %ld", count, *offset, buffer_size);

    size_t bytes_to_copy = min_t(size_t, count, buffer_size - *offset);
    if (bytes_to_copy == 0)
        return 0;

    printk("Bytes to copy %ld", bytes_to_copy);

    int result = copy_to_user(user_space_buffer, kernel_buffer + *offset, bytes_to_copy);

    if(result != 0){
        printk("FAILURE");
        return -EFAULT;
    }

    *offset += bytes_to_copy;
    return bytes_to_copy;
}

static ssize_t ayush_write(struct file *file_pointer, 
                            const char __user *user_space_buffer, 
                            size_t count,
                            loff_t *offset){

    if(buffer_size + count > BUFFER_SIZE - 1)
         count = BUFFER_SIZE - buffer_size - 1; //Limit only till 1024 characters to prevent overflow 

    if(count<0)
        return -ENOSPC;

    printk("Write Function");
    printk("Count %ld, Offset %lld, Buffer Size %ld", count, *offset, buffer_size);

    int result = copy_from_user(kernel_buffer + buffer_size, user_space_buffer, count);

    if(result != 0){
        printk("FAILURE");
        return -EFAULT;
    }

    kernel_buffer[buffer_size + count]='\0';

    buffer_size += count;

    printk("Received from user: %s\n", kernel_buffer);
    return count;
}


static int ayush_module_init(void){
    printk("Hello there from new module init section\n");
    /* struct proc_dir_entry *proc_create(const char *name, 
                                        umode_t mode, 
                                        struct proc_dir_entry *parent, 
                                        const struct proc_ops *proc_ops); */

    kernel_buffer = kmalloc(BUFFER_SIZE, GFP_KERNEL);
    if(!kernel_buffer){
        printk("Error allocating memory for kernel buffer");
            return -ENOMEM;
    }

    strcpy(kernel_buffer, "Hello From Kernel Module\n");
    buffer_size = strlen(kernel_buffer);

    custom_proc_entry = proc_create("ayush_module", 
                                        0666,
                                        NULL, 
                                        &driver_proc_ops);

    if(custom_proc_entry == NULL){
        kfree(kernel_buffer);
        printk("Error creating proc entry\n");
        return -1;
    }

    printk("Hello there from new module again - Module Loaded\n");
    printk("Exiting init\n");
    return 0;
}

static void ayush_module_exit(void){
    printk("Exiting");
    proc_remove(custom_proc_entry);
    kfree(kernel_buffer);
    printk("Exiting last\n");
}

module_init(ayush_module_init);
module_exit(ayush_module_exit);

