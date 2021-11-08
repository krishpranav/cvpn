# cvpn
A simple vpn written in C

[![forthebadge](https://forthebadge.com/images/badges/made-with-c.svg)](https://forthebadge.com)

# Features:
- this is a cli vpn like openvpn
- Runs on TCP. Works pretty much everywhere, including on public WiFi where only TCP/443 is open or reliable.
- Uses only modern cryptography, with formally verified implementations.
- Small and constant memory footprint. Doesn't perform any heap memory allocations.
- Small (~25 KB), with an equally small and readable code base. No external dependencies.
- Works on Linux, macOS
- Doesn't leak between reconnects if the network doesn't change. Blocks IPv6 on the client to prevent IPv6 leaks.

# Installation:
```
git clone https://github.com/krishpranav/cvpn
cd cvpn
make
./cvpn
```

- Example of using this on a server
```
sudo ./cvpn server vpnserver.key auto 1956
```

- Example of using on the client
```
sudo ./cvpn client vpn.key 34.216.127.34 1959
```

- for disconnection cvpn ```ctrl-c```
