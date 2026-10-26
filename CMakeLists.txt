cmake_minimum_required(VERSION 3.16)

# Override with -DPROJECT_VER=1.1.0 for the next OTA image.
if(NOT DEFINED PROJECT_VER)
    set(PROJECT_VER "1.0.0")
endif()
set(IDF_TARGET "esp32s3" CACHE STRING "Target confirmed by the connected board probe")
set(LAB_VERSION_CODE "1" CACHE STRING "Monotonic signed release version code")
set(LAB_CFG_SCHEMA "1" CACHE STRING "Reader schema: 1 for baseline, 2 for migrated image")
option(LAB_CFG_FAULT_SHADOW_RESET "Negative fixture: reset after schema2 set_blob before commit" OFF)
option(LAB_PREVALID_RESET "Negative fixture: reset after health before SDK VALID" OFF)
option(LAB_FAULT_PROFILE "Compile isolated controlled HTTP fault transport and public test CA" OFF)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(studybook_ota_lab)
