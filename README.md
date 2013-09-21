# wireshark.osc

## an Open Sound Control dissector plugin for Wireshark

This is a wireshark dissector plugin for the Open Sound Control protocol.

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

If the _make install_ target should not work on your system, you can manually put the plugin (osc.so or osc.dll) into the wireshark plugins directory, e.g _/usr/lib/wireshark/plugins/1.10.2/osc.so_.

### filter targets
The  plugin introduces the following hooks you can filter the network stream for:

- osc.bundle
- osc.bundle.timetag
- osc.bundle.element
- osc.bundle.element.size
- osc.message
- osc.message.path
- osc.message.format
- osc.message.int32
- osc.message.float
- osc.message.string
- osc.message.blob
- osc.message.blob.size
- osc.message.blob.data
- osc.message.true
- osc.message.false
- osc.message.nil
- osc.message.bang
- osc.message.int64
- osc.message.double
- osc.message.timetag
- osc.message.symbol
- osc.message.char
- osc.message.rgba
- osc.message.midi

### filter examples
Show all messages with an int32 argument of 13

    osc.message.int32 == 13

Show all messages with blobs of size 44

    osc.message.blob.size == 44

Show all bundles with bundle timetag of 0x0000000000000001

    osc.bundle.timetag == 1

Show all bundles with nested elements (messages or bundles) of size 64

    osc.bundle.element.size == 64

Show all messages with path "/ping"

    osc.message.path == "/ping"

Show all messages which contain "pong" in their path

    osc.message.path contains "pong"

Show all messages with format string ",ifs"

    osc.message.format == ",ifs"

Show all messages with a boolean (true OR false) argument

    osc.message.true or osc.message.false

Show all messages with a true AND false argument

    osc.message.true and osc.message.false

Show all messages with a MIDI on-key event (0x90)

    osc.message.midi[1] == 90 

Show all messages with a MIDI off-key event on channel 7

    (osc.message.midi[1] == 80) and (osc.message.midi[0] == 7)

Show all messages with a float or double of 3.1415926

    (osc.message.float == 3.1415926) or (osc.message.double == 3.1415926)

show all messages with blobs that start with a zero byte

    osc.message.blob.data[0] == 00

### references

<http://www.wireshark.org/>

<http://opensoundcontrol.org/>
