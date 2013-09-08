# wireshark.osc

## an Open Sound Control dissector plugin for Wireshark

This is a wireshark dissector plugin for the Open Sound Control protocol.

### usage

The plugin registers to listen automatically on UDP ports 3333(TUIO), 4444, 6666, 57110(scsynth), 57120(sclang). You may want to add additional ones at the end of "packet-osc.c" with "dissector\_add\_*".

### build and install

    cmake .
    make
    sudo make install


### references

<http://www.wireshark.org/>

<http://opensoundcontrol.org/>
