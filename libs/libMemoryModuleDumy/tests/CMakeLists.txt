add_executable(TestsMemoryModule "Tests.cpp" )
set_property(TARGET TestsMemoryModule PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_link_libraries(TestsMemoryModule MemoryModule )


