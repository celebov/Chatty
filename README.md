# ITC8061

##Group Members
1. Kaan Sadik KARADAG
2. Neslisah Celik
3. Ilhan Celebi

##Requirements
- Python 3.5
- GnuPG
- pycrypto 2.6.1 2.6.1
- pycryptodome 3.4 3.4
- pycryptodomex 3.4.2 3.4.2
- python-gnupg 0.3.8 0.3.8
- scapy-python3 0.18 0.18
- bitstring

###GnuPG Configuration
In order to use GnuPG properly, all keys must be imported and trusted.

**To Import Key**
`gpg —import newkey.txt`

**To Export Key**
`gpg —armor —export you@example.com > mykey.txt`

###Project Configuration
Project takes care of environment variables via its console, asking to the user.

In order to configure GnuPG for the client, change both UUIDs to your own:

```
RoutingTable = [
    {'UUID': 'CB59737D', 'ViaUUID': 'CB59737D', 'Cost': 0}
]
```
Project has an extensive logging system that can also be configured from *Logs/Log-Config.json*

Setting Logging system to *Debug* level will let you see what is happening in the backend.

###Usage
After everything configured, run *ChatApp.py*

Enter appropriate variables for environment for establishing a secure connection.

Commands are used with `#` in system to make them easier to identify. Type `#HELP` to get the list of commands.

Use `#ADDNEIGH` and follow the instructions to add a neighbor. There are ACK waiting processes, be aware of the directions from console. After having ACK, type the username you want for that user.

From now on you can message this user using `#<UserName>`

After Adding Neighbour, you still have to establish a secure session. To do this simply Message the user. This will start Session Establish Process and when console alerts, type in your GPG Passphrase.

Having *Session Established* message, the messages and files you are sending to this user is encrypted.

Type `#<Username> <msg>` to message this user.

To send file, type `#FILE`

To start Routing Table Sharing Protocol type `#ROUT`

