# wireshark.osc

## an Open Sound Control dissector plugin for Wireshark

This is a wireshark dissector plugin for the Open Sound Control protocol.

### usage

The plugin registers to listen automatically on UDP ports 3333(TUIO), 4444, 6666 and UDP/TCP ports 57110(scsynth), 57120(sclang). You may want to add additional ones at the end of "packet-osc.c" with "dissector\_add\_*".

### build and install

    cmake .
    make
    sudo make install

### filter targets
The  plugin introduces the following hooks you can filter the network stream for:

- osc.bundle
- osc.message
- osc.message.blob
- osc.bundle.timestamp
- osc.bundle.size
- osc.message.path
- osc.message.format
- osc.message.int32
- osc.message.float
- osc.message.string
- osc.message.blob.size
- osc.message.blob.data
- osc.message.true
- osc.message.false
- osc.message.nil
- osc.message.bang
- osc.message.int64
- osc.message.double
- osc.message.symbol
- osc.message.char
- osc.message.midi

### filter examples
Show all messages with an int32 argument of 13

    osc.message.int32 == 13

Show all messages with blobs of size 44

    osc.message.blob.size == 44

Show all bundles with bundle timestamp of 00000000:00000001

    osc.bundle.timestamp == 1

Show all bundles with nested structures (messages or bundles) of size 64

    osc.bundle.size == 64

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
