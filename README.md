<p align="center">
  <img src="./figures/ARID_Logo.png" alt="ARID" width="150">
</p>

# Anonymous Remote IDentification of Unmanned Aerial Vehicles (ARID)
ARID provides anonymous remote identification for drones and UAVs.

## Credits
Credits go to the original authors of EC ElGamal protocol (blanclux) and OpenSSL 1.0.0 library for ARM whose original efforts made this possible.

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

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
