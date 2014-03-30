# wireshark.osc

## an Open Sound Control dissector plugin for Wireshark

This is a wireshark dissector plugin for the Open Sound Control protocol.

### **NOTE: THIS CODE HERE HAS BEEN ADDED TO WIRESHARK RECENTLY, IT WILL REMAIN HERE THOUGH UNTIL THE CORRESPONDING WIRESHARK VERSION WILL HAVE BEEN RELEASED**

### usage

The plugin is written as a heuristic dissector, e.g. it will automatically recognize valid OSC packets on any non-assigned UDP and TCP port and bind future communication to the OSC protocol for the remaining session.

### build and install

You need the wireshark headers and the glib-2.0 headers to build the plugin. This project is designed as an out-of-source-tree wireshark dissector plugin and uses CMake as build system, you'll need it, too. On most Linux distributions, there is a wireshark-dev package that installs all the needed headers. On an other OS, e.g. Windows, OS-X, you may need to download the whole wireshark source tree to get to the header files. The CMake build script of this dissector tries to automatically find the wireshark and the glib-2.0 headers. If CMake is not successful, but the headers are present on your system, you can point to them manually.

Ideally, its enough to build the plugin like that:

    cmake .
    make
    sudo make install

To manually tell CMake where the wireshark and glib-2.0 headers are located, run CMake in interactive mode:

    cmake -i .
    make
    sudo make install

Instead of _cmake_, you can of course use its UI helpers _ccmake_ (ncurses) or _cmake-gui_ (Qt).

If the _make install_ target should not work on your system, you can manually put the plugin (osc.so or osc.dll) into the wireshark plugins directory, e.g _/usr/lib/wireshark/plugins/1.10.6/osc.so_.

### references

<http://www.wireshark.org/>

<http://opensoundcontrol.org/>
