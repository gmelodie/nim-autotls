# Package

version       = "0.1.0"
author        = "Gabriel Cruz"
description   = "A new awesome nimble package"
license       = "MIT"
srcDir        = "src"
bin           = @["nim_autotls"]


# Dependencies

requires "nim >= 2.0.14", "https://github.com/vacp2p/nim-libp2p#csr-gen", "bio >= 0.1.0", "jwt >= 0.2", "jsony", "https://github.com/status-im/nim-stew#1f8a5ad7612afebfa5b724b36baefdc85f43b3e8", "ndns >= 0.1.3"
