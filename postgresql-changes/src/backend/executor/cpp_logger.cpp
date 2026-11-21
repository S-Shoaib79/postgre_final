#include <iostream>

// Use extern "C" so C files can call this function
extern "C" {
    void _PGS_myCppFunction(int value) {
        std::cout << "Hello from C++ inside Postgres Executor! Value: " << value << std::endl;
    }
}