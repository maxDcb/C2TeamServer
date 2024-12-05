#include <iostream>

// g++ -fPIC -shared  ./libtest.cpp -o libtest.so

class Test
{
public:
	Test();
	~Test();
};


#ifdef _WIN32
extern "C" __declspec(dllexport) Test * TestConstructor();
#else
extern "C"  __attribute__((visibility("default"))) Test * TestConstructor();
#endif


#ifdef _WIN32
__declspec(dllexport) Test* TestConstructor() 
{
    return new Cat();
}
#else
__attribute__((visibility("default"))) Test* TestConstructor() 
{
    return new Test();
}
#endif


Test::Test()
{
    std::cout << "Test Constructor" << std::endl;
}


Test::~Test()
{
}

