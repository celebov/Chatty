import gnupg
# gpg paramaters
gpg = gnupg.GPG(gnupghome='/home/raziel/.gnupg')  # TYPE YOUR OWN .GNUPG PATH
gpg.encoding = 'utf-8'

#AES Parameters
padValue = b'#'
blockSize = 16

RoutingTable = [
    {'UUID': 'EC8AF480', 'ViaUUID': 'EC8AF480', 'Cost': 0},
]
SessionKeyTable = [

]

KeyIDs = [

]

NeighborTable = [
]

# GNUPG passphrase hardcoded
passphrase = None

Connections = {}