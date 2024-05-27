#pragma once

#include <string>
#include <iostream>


typedef void *HMEMORYMODULE;

HMEMORYMODULE MemoryLoadLibrary(const void *moduleData, size_t size);