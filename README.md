# GWATCH
Gwatch is a tool designed to monitor reads and writes to a specified global variable. For that, it utilizes ```ptrace``` function. So, it runs only on Linux machines.

## Build
GWATCH uses CMake as the build system. To build the whole project, execute the following commands while being in the root of the project:
```
cmake -B build
cmake --build build 
```

## Run GWATCH
Binaries created by CMake are stored under ```build/bin```. After entering this location, you can run gwatch by executing:
```
./gwatch --var <symbol> --exec <path> [-- arg1 ... argN]
```
For example and test purposes, I prepared binary called ```test_file```, which can be used to test GWATCH. So, for example, to inspect writes to the ```xd8``` variable, please run the following:
```
# For testing purposes, test_file requires one command-line argument.
# However, it is not used anywhere, so e.g. here I pass a "something" string.
./gwatch --var xd8 --exec test_file -- something
```

## Test GWATCH
For testing. GWATCH uses GTest binded with CMake. So, to run the tests, perform th efollowing commands while being in the root of the project:
```
cd build
ctest
```


