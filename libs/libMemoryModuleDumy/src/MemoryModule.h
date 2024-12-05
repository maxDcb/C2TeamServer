#pragma once

#include <string>
#include <iostream>


typedef void *HMEMORYMODULE;

HMEMORYMODULE MemoryLoadLibrary(const void *moduleData, size_t size);

void MemoryFreeLibrary(HMEMORYMODULE mod);

void* MemoryGetProcAddress(HMEMORYMODULE mod, const char* procName);