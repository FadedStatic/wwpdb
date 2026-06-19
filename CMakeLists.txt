cmake_minimum_required(VERSION 4.3)
project(wwpdb)

set(CMAKE_CXX_STANDARD 26)

add_executable(wwpdb main.cpp wwpdb.hpp
        nlohmann/json.hpp)
