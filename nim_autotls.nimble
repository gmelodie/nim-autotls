# Package

version       = "0.1.0"
author        = "Gabriel Cruz"
description   = "A new awesome nimble package"
license       = "MIT"
srcDir        = "src"
bin           = @["nim_autotls"]


# Dependencies

requires "nim >= 2.0.14", "libp2p >= 1.9.0", "bio >= 0.1.0", "jwt >= 0.2", "jsony", "stew >= 0.3.0"
