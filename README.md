<p align="center">
  <img src="./figures/ARID_Logo.png" alt="ARID" width="150">
</p>

# Anonymous Remote IDentification of Unmanned Aerial Vehicles (ARID)
ARID provides anonymous remote identification for drones and UAVs.

## How to Compile
To compile from source or use a different security level for ```arid.c```, select the correspondent elliptic curve and use the following command:
```arm-linux-gnueabihf-gcc -I ./mavlink-solo/build/common/ -I /usr/local/openssl/include/ -I /usr/local/include/ -L /usr/local/openssl/lib/ -mcpu=cortex-a9 -o arid arid.c -lcrypto -lpthread -Wl,--no-as-needed -ldl -static```

## Hardware Requirements
- A laptop equipped with GNU/Linux distro, and the GNU Arm Embedded Toolchain.
- A programmable drone (like the 3DR Solo Drone) that supports ELF 32-bit LSB executable.
- (optional) An ALFA Card AWUS036NH connected to the laptop.

## Security Level
In order to set a different security level, you can uncomment the correspondent elliptic curve (and the relative buffer). Following table provides information about the different security levels. Finally, compile the program and upload it on the drone.

<table>
  <tr>
    <th style="text-align:center"><b>Security Level (bits)</b></th>
    <th><i><b>Description</b></i></th>
  </tr>
  <tr>
    <td style="text-align:center">80</td>
     <td>With the elliptic curve _secp160r1_ the total size of the MavLink payload is 147 bytes.</td>
  </tr>
  <tr>
    <td style="text-align:center">96</td>
    <td>With the elliptic curve _secp192k1_ the total size of the payload is 163 bytes.</td>
  </tr>
  <tr>
    <td style="text-align:center">112</td>
    <td>With the elliptic curve _secp224k1_ the total size of the payload is 179 bytes.</td>
  </tr>
  <tr>
    <td style="text-align:center">128</td>
    <td>With the elliptic curve _secp256k1_ the total size of the payload is 195 bytes.</td>
  </tr>
</table>

## Change UAV/Drone MAC Address
It is easy to change the UAV/Drone MAC address. You just need to open an SSH session with the drone and execute the script ```change_mac.sh``` inside the drone before the flight. In this case you will not reveal your legitimate MAC address to potential adversaries.
```
ifconfig wlan0 down
ifconfig wlan0 hw ether 12:34:56:78:12:34
ifconfig wlan0 up
ifconfig
```

## Credits
Credits go to the original authors of EC ElGamal protocol (blanclux) and OpenSSL 1.0.0 library for ARM whose original efforts made this possible.

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## Disclaimer
Any actions and or activities related to the material contained within this github repository is solely your responsibility. The misuse of the information in this repository can result in criminal charges brought against the persons in question. The author(s) will not be held responsible in the event any criminal charges be brought against any individuals misusing the information in this repository to break the law.

## Formal verification with ProVerif
The security properties of `ARID` have been verified formally and experimentally by using the open-source tool <a href="https://prosecco.gforge.inria.fr/personal/bblanche/proverif/">ProVerif 2.02pl1</a>, demonstrating enhanced security protection with respect to state-of-the-art approaches.

In order to test the security properties, download the file <a href="./proverif/arid.pv">arid.pv</a> and run: `./proverif arid.pv | grep "RESULT"`.

<p align="center">
  <img src="./figures/proverif.png" alt="ARID" width="700">
</p>

## Developers
Anonymous Authors

## License
```ARID``` is released under the GNU General Public License v3.0 <a href="LICENSE">license</a>.
