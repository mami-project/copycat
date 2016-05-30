# udptun

**TCP tunneling over UDP**
<p align="center">
<img src="./fig/copycat.png" alt="udptun">
</p>
-------------
## Important Files
- src/udptun: binary executable
- udptun.cfg: configuration file
- dest.txt: destination file 
    each line should describe one destination with as followed
    IPv4:
	\<unique-source-port\> \<public-address\> \<private-address\>
    IPv6:
        \<unique-source-port\> \<public-address4\> \<private-address4\> \<public-address6\> \<private-address6\>

## Libs
- libglib-devel/libglib-dev (>= 1.2.10) or libglib-2.0-devel/libglib-2.0-dev
- libpcap

-------------
### Contact
@ekorian
