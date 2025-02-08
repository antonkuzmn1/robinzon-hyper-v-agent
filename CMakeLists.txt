cmake_minimum_required(VERSION 3.10)
project(HyperVAgent)

set(CMAKE_CXX_STANDARD 17)

add_executable(HyperVAgent src/main.cpp)

set_target_properties(HyperVAgent PROPERTIES OUTPUT_NAME "HyperVAgent.exe")

#x86_64-w64-mingw32-g++ -static -o HyperVAgent.exe ../src/main.cpp -lole32 -loleaut32 -luuid -lwbemuuid -lcomsuppw