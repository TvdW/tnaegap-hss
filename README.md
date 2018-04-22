# tnaegap-hss
ssh-agent proxy for Windows applications that only speak Pageant

The pageant.exe implementation that comes with PuTTY has a very limited implementation of the agent protocol. To work around this, I wrote this small agent which allows Windows applications to use the regular OpenSSH ssh-agent instead of Pageant. This enables the usage of many new ciphersuites, SSH certificates, and more.

## Installation

### From a binary release

(TODO)

### From source

    git clone https://github.com/TvdW/tnaegap-hss
    cd tnaegap-hss
    make
    ./tnaegap-hss &

## What's with the name?

`reverse("ssh-pageant") = "tnaegap-hss"`. @cuviper built the exact inverse of what I needed already, and it's called [ssh-pageant](https://github.com/cuviper/ssh-pageant). 

## License

Gnu Public License (GPL), version 3 or later
