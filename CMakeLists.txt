cmake_minimum_required(VERSION 2.8)

project(wireshark.osc)

# pkg-config
find_package(PkgConfig) # ${PKG_CONFIG_FOUND}

# glib-2.0
pkg_search_module(GLIB2 REQUIRED glib-2.0)
include_directories(${GLIB2_INCLUDE_DIRS})

# wireshark
find_path(WIRESHARK_INCLUDE_DIRS epan/packet.h PATH_SUFFIXES wireshark)
include_directories(${WIRESHARK_INCLUDE_DIRS})

find_path(WIRESHARK_PLUGIN_DIRS gryphon.so PATH_SUFFIXES wireshark/plugins/1.10.1 wireshark/plugins wireshark PATHS /usr/lib /usr/local/lib)

# Open Sound Control dissector plugin
add_library(osc MODULE packet-osc.c)
set_target_properties(osc PROPERTIES PREFIX "")
install(TARGETS osc DESTINATION ${WIRESHARK_PLUGIN_DIRS})
