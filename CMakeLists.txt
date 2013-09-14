cmake_minimum_required(VERSION 2.8)

project(wireshark.osc)

# pkg-config
find_package(PkgConfig) # ${PKG_CONFIG_FOUND}

# glib-2.0
pkg_search_module(GLIB2 REQUIRED glib-2.0)
include_directories(${GLIB2_INCLUDE_DIRS})

# wireshark include dirs
find_path(WIRESHARK_INCLUDE_DIRS epan/packet.h PATH_SUFFIXES wireshark)
include_directories(${WIRESHARK_INCLUDE_DIRS})

# abort when wireshark include dirs not found
if(${WIRESHARK_INCLUDE_DIRS} STREQUAL "WIRESHARK_INCLUDE_DIRS-NOTFOUND")
	message(FATAL_ERROR "wireshark include dirs not found")
endif(${WIRESHARK_INCLUDE_DIRS} STREQUAL "WIRESHARK_INCLUDE_DIRS-NOTFOUND")

# extract version
file(READ ${WIRESHARK_INCLUDE_DIRS}/config.h WIRESHARK_CONFIG_H)
string(REGEX MATCH "#define VERSION \"([^\"]+)\"" WIRESHARK_VERSION ${WIRESHARK_CONFIG_H})
set(WIRESHARK_VERSION ${CMAKE_MATCH_1})

# print wireshark include dir and version number
message(STATUS "wireshark include dir: ${WIRESHARK_INCLUDE_DIRS}")
message(STATUS "wireshark version: ${WIRESHARK_VERSION}")

# wireshark plugin dirs
find_path(WIRESHARK_PLUGIN_DIRS gryphon.so PATH_SUFFIXES wireshark/plugins/${WIRESHARK_VERSION} wireshark/plugins wireshark PATHS /usr/lib /usr/local/lib)

# abort when wireshark plugin dirs not found
if(${WIRESHARK_PLUGIN_DIRS} STREQUAL "WIRESHARK_PLUGIN_DIRS-NOTFOUND")
	message(FATAL_ERROR "wireshark dissector plugin dirs not found")
endif(${WIRESHARK_PLUGIN_DIRS} STREQUAL "WIRESHARK_PLUGIN_DIRS-NOTFOUND")

#print wireshark plugin dirs
message(STATUS "wireshark dissector plugin dir: ${WIRESHARK_PLUGIN_DIRS}")

# Open Sound Control dissector plugin
add_library(osc MODULE packet-osc.c)
set_target_properties(osc PROPERTIES PREFIX "")
install(TARGETS osc DESTINATION ${WIRESHARK_PLUGIN_DIRS})
