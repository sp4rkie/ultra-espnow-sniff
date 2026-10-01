# For more information about build system see
# https://docs.espressif.com/projects/esp-idf/en/latest/api-guides/build-system.html
# The following five lines of boilerplate have to be in your project's
# CMakeLists in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 4.0)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
# the warning flags the author's build driver (buildit) passes to every build - the code
# relies on them
idf_build_set_property(COMPILE_OPTIONS "-Wno-parentheses" APPEND)
idf_build_set_property(COMPILE_OPTIONS "-Wno-missing-field-initializers" APPEND)
project(ultra-espnow-sniff)
