def main():
        driver_handle = open("/proc/ayush_module", "r")
        message_from_kernel_space = driver_handle.read()
        print("Initial Message from kernel:")
        print(message_from_kernel_space)
        driver_handle.close()

        driver_handle = open("/proc/ayush_module", "w")
        message = ["\nThis is some message from usr app\n"]
        driver_handle.writelines(message)
        driver_handle.close()

        driver_handle = open("/proc/ayush_module", "r")
        message_from_kernel_space = driver_handle.read()
        print("Updated Message from kernel: ")
        print(message_from_kernel_space)
        driver_handle.close()

        return

main()