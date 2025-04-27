# Package

version       = "0.1.0"
author        = "Gabriel Cruz"
description   = "A new awesome nimble package"
license       = "MIT"
srcDir        = "src"
bin           = @["nim_autotls"]


# Dependencies

requires "nim >= 2.0.14", "https://github.com/vacp2p/nim-libp2p#e6289dc8b09186691bbaa3855f642771fa848bc9", "bio >= 0.1.0", "jwt >= 0.2", "jsony", "stew >= 0.3.0", "ndns >= 0.1.3"
