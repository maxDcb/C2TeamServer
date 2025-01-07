#include "MemoryModule.h"

#include <fstream>

#include <dlfcn.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <unistd.h>


void generateRandomShmName(char *name, size_t length) 
{
    // Define the character set to choose from
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    size_t charsetSize = sizeof(charset) - 1;

    // Seed the random number generator (if not already done)
    srand(time(NULL));

    // Generate random characters
    for (size_t i = 0; i < length; i++) {
        int randomIndex = rand() % charsetSize;
        name[i] = charset[randomIndex];
    }

    // Null-terminate the string
    name[length] = '\0';
}


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


HMEMORYMODULE MemoryLoadLibrary(const void *moduleData, size_t size)
{
	char shmName[6];
	generateRandomShmName(shmName, 5);

	// 
	// create the shms
	//
	int shm_fd;

	// std::cout << "kernel_version() " << kernel_version() << std::endl;

	//If we have a kernel < 3.17
	if (kernel_version() == 0) 
	{
		shm_fd = shm_open(shmName, O_RDWR | O_CREAT, S_IRWXU);
		if (shm_fd < 0) 
		{ 
			// fprintf(stderr, "[-] Could not open file descriptor\n");
			return nullptr;
		}
	}
	// If we have a kernel >= 3.17
	else 
	{
		shm_fd = memfd_create(shmName, 1);
		if (shm_fd < 0) 
		{
			// fprintf(stderr, "[-] Could not open file descriptor\n");
			return nullptr;
		}
	}

	// memcpy in shm
	write(shm_fd, moduleData, size);
	
	void *handle=NULL;

	// printf("[+] Trying to load Shared Object!\n");
	if(kernel_version() == 0) 
	{
		std::string path = "/dev/shm/";
		path+=shmName;

		handle = dlopen(path.c_str(), RTLD_LAZY);

		close(shm_fd);
		shm_unlink(path.c_str());
	} 
	else 
	{	
		// When we pass the file descriptor, as the number is alwayse the same dlopen give use the same handle everytime
		// We create a syslink with a random name to bypass this restriction
		std::string path = "/proc/";
		path+=std::to_string(getpid());
		path+="/fd/";
		path+=std::to_string(shm_fd);

		std::string symlinkPath = "/tmp/";
		symlinkPath+=shmName;

		symlink(path.c_str(), symlinkPath.c_str());

		handle = dlopen(symlinkPath.c_str(), RTLD_LAZY);

		unlink(symlinkPath.c_str());
		close(shm_fd);
	}	

	return handle;
}


void MemoryFreeLibrary(HMEMORYMODULE mod)
{
	dlclose(mod);
}


void* MemoryGetProcAddress(HMEMORYMODULE mod, const char* procName)
{
	return dlsym(mod, procName);
}