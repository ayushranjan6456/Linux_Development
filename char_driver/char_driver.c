#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/module.h>
#include<linux/kdev_t.h>
#include<linux/fs.h>
#include<linux/cdev.h>
#include<linux/slab.h>
#include<linux/uaccess.h>
#include<linux/device.h>
#include<linux/ioctl.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ayush Ranjan");
MODULE_DESCRIPTION("The Character Device Driver");


// Define the IOCTL code
#define WR_DATA _IOW('a','a', int32_t*)
#define RD_DATA _IOR('a','b', int32_t*)

#define mem_size 1024

static int32_t val = 0;
static dev_t dev = 0;
static struct class *dev_class;
static struct cdev my_cdev;

uint8_t *kernel_buffer;

static int __init char_driver_init(void);
static void __exit char_driver_exit(void);

static int my_open(struct inode *inode, struct file *file);
static int my_release(struct inode *inode, struct file *file);
static ssize_t my_read(struct file *file_ptr, char __user *buf, size_t len, loff_t *offset);
static ssize_t my_write(struct file *file_ptr, const char *buf, size_t len, loff_t *offset);

static long char_ioctl(struct file *file, unsigned int cmd, unsigned long arg);



static const struct file_operations fops = {
        .owner          = THIS_MODULE,
        .read           = my_read,
        .write          = my_write,
        .open           = my_open,
        .release        = my_release,
        .unlocked_ioctl = char_ioctl
};


static int my_open(struct inode *inode, struct file *file){
        //Creating Physical Memory
        if((kernel_buffer = kmalloc(mem_size, GFP_KERNEL)) == 0){
                printk(KERN_INFO"Cannot allocate memory to the kernel");
                return -1;
        }
        printk(KERN_INFO"Device file opened\n");
        return 0;
}


static int my_release(struct inode *inode, struct file *file){
        kfree(kernel_buffer);
        printk(KERN_INFO"Device File closed\n");
        return 0;
}


static ssize_t my_read(struct file *file_ptr, char __user *buf, size_t len, loff_t *offset){
        if(copy_to_user(buf, kernel_buffer, mem_size) != 0){
                return -EFAULT;
        }
        printk(KERN_INFO"Data read: Done\n");
        return mem_size;
}

static ssize_t my_write(struct file *file_ptr, const char *buf, size_t len, loff_t *offset){
        if(copy_from_user(kernel_buffer, buf, len) != 0){
                return -EFAULT;
        }
        printk(KERN_INFO"Data written successfully\n");
        return len;
}

static long char_ioctl(struct file *file, unsigned int cmd, unsigned long arg){
        switch(cmd){
                case WR_DATA:
                        copy_from_user(&val, (int32_t*)arg, sizeof(val));
                        printk(KERN_INFO"val = %d\n", val);
                        break;
                case RD_DATA:
                        copy_to_user((int32_t*)arg, &val, sizeof(val));
                        break;
        }
        return 0;
}


static int __init char_driver_init(void){
    //Allocating the Major Number
    if(alloc_chrdev_region(&dev, 0, 1,"my_dev") < 0){
        printk("Cannot allocarte the major number\n");
        return -1;
    }

    printk(KERN_INFO"Major: %d Minor %d",MAJOR(dev), MINOR(dev));

    // Creating a cdev structure
    cdev_init(&my_cdev, &fops);

    // Adding character device to the system
    if((cdev_add(&my_cdev,dev,1)) < 0){
        printk(KERN_INFO"Cannot add device to the system\n");
        unregister_chrdev_region(dev, 1);
        return -1;
    }

    //Creating a class
    if((dev_class = class_create("my_class")) == NULL){
        printk(KERN_INFO"Cannot Create the struct class\n");
        cdev_del(&my_cdev);
        unregister_chrdev_region(dev,1);
        return -1;
    }

    //Creating device
    if((device_create(dev_class, NULL, dev, NULL, "my_device")) == NULL){
        printk(KERN_INFO"Cannot create the device");
        class_destroy(dev_class);
        cdev_del(&my_cdev);
        unregister_chrdev_region(dev,1);
        return -1;
    }

    return 0;
}


static void __exit char_driver_exit(void){
        device_destroy(dev_class, dev);
        class_destroy(dev_class);
        cdev_del(&my_cdev);
        unregister_chrdev_region(dev,1);
        printk(KERN_INFO"Device driver removed successfully");
}


module_init(char_driver_init);
module_exit(char_driver_exit);