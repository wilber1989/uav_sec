#!~/bin/bash
cd ../library/
make clean
make
cd ../lib
cp ../library/lib* .
cd ../src
make clean
make
