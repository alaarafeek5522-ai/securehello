cmake_minimum_required(VERSION 3.22.1)
project("security")

add_library(
    security
    SHARED
    src/main/cpp/security.cpp
)

find_library(log-lib log)

target_link_libraries(
    security
    ${log-lib}
)
