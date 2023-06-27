# UWB RTLS Tools
A collection of utilities and tools related to Ultra-Wideband Real Time Locating Systems. This material is released in conjunction with our presentation at Black Hat 22 ["UWB Real Time Locating Systems: How Secure Radio Communications May Fail in Practice"](https://www.blackhat.com/us-22/briefings/schedule/#uwb-real-time-locating-systems-how-secure-radio-communications-may-fail-in-practice-27106).

In this repository, for each UWB RTLS vendor analyzed, you may find a dissector and a baseline PCAP of the commmunications among the UWB anchors and the RTLS server.


# Sewio UWB RTLS
The Wireshark dissector for the custom protocol used by the Sewio UWB RTLS has been written in Lua to be portable and easy to use.

## Installation
The Lua script is natively supported by Wireshark and there are no required dependencies for using it. The script needs to be placed in the right directory depending on the operating system used. Below are the reported working paths used during development:

* Linux / MacOS: ```~/.config/wireshark/plugins```
* Windows: ```%appdata%\Wireshark\plugins```

Note that in some systems the plug-in folder could be missing. To fix this issue, just create it manually and place the Lua script in it.

More detailed information about plug-in installation can be found at the official web page:
[https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html)

## Features
The dissector interprets all Sewio UWB RTLS protocol options that were noticed in the anchors-server communications during the tests, populating the description fields for the specific analysed packets. More details regarding the packet dissection are available in the research whitepaper, that can be freely downloaded from the Black Hat briefing page or from the [labs blog of the Nozomi Networks](https://www.nozominetworks.com/blog/nozomi-networks-researchers-reveal-zero-day-rtls-vulnerabilities-at-black-hat-22/) website. Among others, the dissector is able to parse the following messages:
* The ```syncEmission``` message is sent by the reference anchor and contains the synchronization timestamp when it generated the sync UWB signal;
* The ```syncArrival``` message is sent by the non-reference anchors and contains the synchronization timestamps when they received the UWB signal generated by the reference one;
* The ```blink``` message is sent by all anchors and contains the positioning timestamps related to monitored tags.

Please, consider that, in order to convert the timestamps reported in the packets to their equivalent in seconds, it is necessary to divide the value shown by the dissector by ```128*499.2E6```. The time units used by Sewio UWB RTLS are those defined in the IEEE standard and native to the Decawave DW1000, where the LSB represents 1/128 of the fundamental UWB frequency (499.2 MHz), or approximately 15.65 picoseconds.

You may test the dissector with the provided PCAP file, captured during an execution of the RTLS while moving UWB tags in the monitored room. 

We would like to emphasize that the functionality of the dissector is the result of our analysis and reflects an attacker’s reverse engineering of the Sewio UWB RTLS protocol.


# Avalue UWB RTLS
The Wireshark dissector for the custom protocol used by the Avalue UWB RTLS has been written in Lua to be portable and easy to use.

## Installation
Please refer to the same installation instructions written in the Sewio UWB RTLS section.

## Features
The dissector interprets all Avalue UWB RTLS protocol packet types that were noticed in the anchors-server communications during the tests, populating the description fields for the specific analysed packets. More details regarding the packet dissection are available in the research whitepaper, that can be freely downloaded from the Black Hat briefing page or from the [labs blog of the Nozomi Networks](https://www.nozominetworks.com/blog/nozomi-networks-researchers-reveal-zero-day-rtls-vulnerabilities-at-black-hat-22/) website. Notably, the dissector is currently able to parse the following packet types:
* The ```CCP``` packet is sent by the non-reference anchors and contains both the transmission synchronization timestamp (the instant when the reference anchor has sent the UWB signal), as well as the receiving synchronization timestamp (the instant when the non-reference anchor has received the UWB signal). The reference anchor does not send any CCP packets on the network. The timestamp is already reported in seconds;
* The ```TDoA``` packet is sent by all anchors and contains the positioning timestamps related to monitored tags. The timestamp is already reported in seconds.

You may test the dissector with the provided PCAP file, captured during an execution of the RTLS while moving UWB tags in the monitored room. 

We would like to emphasize that the functionality of the dissector is the result of our analysis and reflects an attacker’s reverse engineering of the Avalue UWB RTLS protocol.


# Ubisense UWB RTLS
The Wireshark dissector for the custom protocol used by the Ubisense UWB RTLS has been written in Lua to be portable and easy to use.

## Installation
Please refer to the same installation instructions written in the Sewio UWB RTLS section.

## Features
The dissector interprets the packets with message code ```0x026B``` (D4 Tag Location), that is the message code that is used by the sensors to communicate the position of a tag to the server. More details regarding the packet dissection are available in the [labs blog of the Nozomi Networks](https://www.nozominetworks.com/blog/uwb-rtls-vulnerability-confirmed-in-ubisense-dimension4-3d-tracking-system/) website. Notably, differently than the Sewio and Avalue UWB RTLS, in the Ubisense UWB RTLS the network packets contain the X, Y, and Z coordinates of the tag, because the different network architecture allows anchors to be kept in sync and immediately communicate the final position to the server.

You may test the dissector with the provided PCAP file, captured during an execution of the RTLS while moving UWB tags in the monitored room. 

We would like to emphasize that the functionality of the dissector is the result of our analysis and reflects an attacker’s reverse engineering of the Ubisense UWB RTLS protocol.
