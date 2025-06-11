#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<fcntl.h>
#include<unistd.h>
#include<sys/ioctl.h>

#define DEVICE_PATH "/dev/my_device"

#define WR_DATA _IOW('a','a', int32_t*)
#define RD_DATA _IOR('a','b', int32_t*)

int main()
{
	int fd;
	int32_t val, num;

	printf("----Demo of Character Device Driver----\n");

	fd = open(DEVICE_PATH, O_RDWR);
	if(fd < 0){
		printf("Cannot Open Devcice file \n");
		return 1;
	}

	printf("Enter the data to send \n");
	scanf("%d", &num);
	ioctl(fd, WR_DATA, (int32_t*)&num);
	printf("Wrote data from driver\n");

	printf("Reading data from driver\n");
	ioctl(fd, RD_DATA, (int32_t*)&val);
	printf("Data: %d\n", val);
	printf("Closing...\n");

	close(fd);
}
