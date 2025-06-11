#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<fcntl.h>
#include<unistd.h>


#define DEVICE_PATH "/dev/my_device"

int8_t write_buf[1024];
int8_t read_buf[1024];

int main()
{
        int fd;
        char option;

        printf("----Demo of Character Device Driver----\n");

        fd = open(DEVICE_PATH, O_RDWR);
        if(fd < 0){
                printf("Cannot Open Devcice file \n");
                return 1;
        }

        while(1){
                printf("-------Please Enter Your Choice------\n");
                printf("1. Read\n");
                printf("2. Write\n");
                printf("3. Exit\n");
                scanf("%c", &option);
                printf("You chose %c\n", option);

                switch(option){
                        case '1':
                                printf("Reading the data\n");
                                read(fd, read_buf, 1024);
                                printf("Done\n");
                                printf("Data : \n %s\n", read_buf);
                                break;
                        case '2':
                                printf("Enter the data to be written\n");
                                scanf("%[^\t\n]s", write_buf);
                                printf("Writing Data...\n");
                                write(fd, write_buf, strlen(write_buf)+1);
                                printf("Done\n");
                                break;
                        case '3':
                                close(fd);
                                exit(1);
                                break;
                        default:
                                printf("Enter a valid option\n");
                                break;
                }

        }
        close(fd);
}