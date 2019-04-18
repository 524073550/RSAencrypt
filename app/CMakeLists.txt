# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.4.1)

include_directories(libs/include)

# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.

add_library( # Sets the name of the library.
        encrypt
        # Sets the library as a shared library.
        SHARED
        # Provides a relative path to your source file(s).
        src/main/cpp/encrypt.cpp)

add_library(crypto SHARED IMPORTED)
add_library(ssl SHARED IMPORTED)

set_target_properties(crypto PROPERTIES IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/libs/lib/${ANDROID_ABI}/libcrypto.so)
set_target_properties(ssl PROPERTIES IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/libs/lib/${ANDROID_ABI}/libssl.so)

find_library( # Sets the name of the path variable.
        log-lib

        # Specifies the name of the NDK library that
        # you want CMake to locate.
        log)

target_link_libraries( # Specifies the target library.
        encrypt
        crypto
        ssl
        # Links the target library to the log library
        # included in the NDK.
        ${log-lib} )