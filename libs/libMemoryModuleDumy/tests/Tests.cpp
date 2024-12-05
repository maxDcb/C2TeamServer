#include <fstream>

#include "MemoryModule.h"

typedef void* (*constructProc)();


// g++ -fPIC -shared  ./libtest.cpp -o libtest.so
int main()
{
	std::string inputFile = "libtest.so";

	std::ifstream input;
	input.open(inputFile, std::ios::binary);

	if( input ) 
	{
		std::string buffer(std::istreambuf_iterator<char>(input), {});

		void* handle = NULL;
		handle = MemoryLoadLibrary((char*)buffer.data(), buffer.size());
		if (handle == NULL)
		{
			return false;
		}
		
		std::string funcName = "TestConstructor";

		constructProc construct;
		construct = (constructProc)MemoryGetProcAddress(handle, funcName.c_str());
		if(construct == NULL) 
		{
			return false;
		}

		construct();

		MemoryFreeLibrary(handle);

		return true;
	}

	return false;
}