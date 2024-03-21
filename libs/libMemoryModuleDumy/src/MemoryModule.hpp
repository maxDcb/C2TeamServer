#pragma once

#include <thread>
#include <string>
#include <iostream>


typedef void *HMEMORYMODULE;

HMEMORYMODULE MemoryLoadLibrary(const void *, size_t);