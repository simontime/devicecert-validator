cmake_minimum_required(VERSION 3.2)
project(devicecert-validator)

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 11)

add_executable(devicecert-validator
    ec.c
    main.cpp)
