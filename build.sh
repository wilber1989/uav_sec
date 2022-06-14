#!/bin/sh
if [ "$1"x = "clean"x ];then
    if [ -d "bin" ];then
        rm -r bin
    fi
    if [ -d "build" ];then
        rm -r build
    fi
    if [ -d "lib" ];then
        rm -r lib
    fi
    echo "#####clean!#####"
elif [ "$1"x = ""x ];then
    if [ -d "build" ];then
        rm -r build
    fi
    mkdir -p build
    cd build
    cmake ..
    make
    make install

    echo "#####build end !#####"
else
    echo "-----param error!-----"
fi