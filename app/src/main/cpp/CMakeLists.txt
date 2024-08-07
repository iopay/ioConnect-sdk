# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html.
# For more examples on how to use CMake, see https://github.com/android/ndk-samples.

# Sets the minimum CMake version required for this project.
cmake_minimum_required(VERSION 3.22.1)

# Declares the project name. The project name can be accessed via ${ PROJECT_NAME},
# Since this is the top level CMakeLists.txt, the project name is also accessible
# with ${CMAKE_PROJECT_NAME} (both CMake variables are in-sync within the top level
# build script scope).
project("ndktest")

# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.
#
# In this top level CMakeLists.txt, ${CMAKE_PROJECT_NAME} is used to define
# the target library name; in the sub-module's CMakeLists.txt, ${PROJECT_NAME}
# is preferred for the same purpose.
#
# In order to load a library into your app from Java/Kotlin, you must call
# System.loadLibrary() and pass the name of the library defined here;
# for GameActivity/NativeActivity derived applications, the same library name must be
# used in the AndroidManifest.xml file.

#set(JNI_LIBS_DIR ${CMAKE_SOURCE_DIR}/../jniLibs/${ANDROID_ABI})
#message("jniLibs: ${JNI_LIBS_DIR}")
#
#find_library(SCRYPT_LIBRARY NAMES scrypt PATHS ${JNI_LIBS_DIR} NO_DEFAULT_PATH)
#if (SCRYPT_LIBRARY)
#    message(FATAL_ERROR "Found library: ${SCRYPT_LIBRARY}")
#else ()
#    message(FATAL_ERROR "Library not found")
#endif ()

set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY BOTH)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE BOTH)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM BOTH)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE BOTH)
set(JNI_LIBS_DIR ${CMAKE_SOURCE_DIR}/../jniLibs/${ANDROID_ABI})
message("jniLibs: ${JNI_LIBS_DIR}")
message("CMAKE_PROJECT_NAME: ${CMAKE_PROJECT_NAME}")

add_library(${CMAKE_PROJECT_NAME} SHARED ioconnect-lib.cpp)

add_library(ioconnect SHARED IMPORTED)
set_target_properties(
        ioconnect
        PROPERTIES IMPORTED_LOCATION
        ${JNI_LIBS_DIR}/libioconnect.so)

include_directories(${CMAKE_SOURCE_DIR}/include/)

target_link_libraries(
        ${CMAKE_PROJECT_NAME}
        ioconnect
        log)