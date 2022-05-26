cmake_minimum_required (VERSION 2.6)
project (uav_sec)

set(CMAKE_INSTALL_PREFIX ${CMAKE_SOURCE_DIR})
message("CMAKE_SOURCE_DIR:${CMAKE_SOURCE_DIR}")
add_subdirectory(deCORE_Crypto-S)
add_subdirectory(uav_src)
