#include "MemoryModule.h"

#include <vector>
#include <fstream>

#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

#define SHM_NAME "testshm"


int kernel_version() 
{
	struct utsname buffer;
	uname(&buffer);
	
	// printf("system name = %s\n", buffer.sysname);
    // printf("node name   = %s\n", buffer.nodename);
    // printf("release     = %s\n", buffer.release);
    // printf("version     = %s\n", buffer.version);
    // printf("machine     = %s\n", buffer.machine);	

    long ver[16];
    char* p = buffer.release;
    int i=0;

    while (*p) {
        if (isdigit(*p)) {
            ver[i] = strtol(p, &p, 10);
            i++;
        } else {
            p++;
        }
    }

    // printf("Kernel %ld Major %ld Minor %ld Patch %ld\n", ver[0], ver[1], ver[2], ver[3]);

	if (ver[0] < 3)
		return 0;
	else if (ver[0] > 3)
		return 1;
	if (ver[1] < 17)
		return 0;
	else
		return 1;
}


int open_ramfs(void) 
{
	int shm_fd;

	//If we have a kernel < 3.17
	if (kernel_version() == 0) 
	{
		// https://man7.org/linux/man-pages/man3/shm_open.3.html
		shm_fd = shm_open(SHM_NAME, O_RDWR | O_CREAT, S_IRWXU);
		if (shm_fd < 0) 
		{
			fprintf(stderr, "[-] Could not open file descriptor\n");
			exit(-1);
		}
	}
	// If we have a kernel >= 3.17
	else 
	{
		// https://man7.org/linux/man-pages/man2/memfd_create.2.html
		shm_fd = memfd_create(SHM_NAME, 1);
		if (shm_fd < 0) 
		{
			fprintf(stderr, "[-] Could not open file descriptor\n");
			exit(-1);
		}
	}
	return shm_fd;
}


HMEMORYMODULE MemoryLoadLibrary(const void *moduleData, size_t size)
{
	// 
	// create the shms
	//
	int shm_fd;

	std::cout << "kernel_version() " << kernel_version() << std::endl;

	//If we have a kernel < 3.17
	if (kernel_version() == 0) 
	{
		shm_fd = shm_open(SHM_NAME, O_RDWR | O_CREAT, S_IRWXU);
		if (shm_fd < 0) 
		{ 
			fprintf(stderr, "[-] Could not open file descriptor\n");
			return nullptr;
		}
	}
	// If we have a kernel >= 3.17
	else 
	{
		shm_fd = memfd_create(SHM_NAME, 1);
		if (shm_fd < 0) 
		{
			fprintf(stderr, "[-] Could not open file descriptor\n");
			return nullptr;
		}
	}

	// memcpy in shm
	write(shm_fd, moduleData, size);

	char path[1024];
	void *handle=NULL;

	printf("[+] Trying to load Shared Object!\n");
	if (kernel_version() == 1) 
	{
		snprintf(path, 1024, "/proc/%d/fd/%d", getpid(), shm_fd);
	} 
	else 
	{
		close(shm_fd);
		snprintf(path, 1024, "/dev/shm/%s", SHM_NAME);
	}

	handle = dlopen(path, RTLD_LAZY);

	close(shm_fd);

	return handle;
}