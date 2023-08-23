```
               _     _           
 ___ _ _ _ _ _|_|___| |_ ___ _ _ 
| . | | | | | | |   | . | . |_'_|
|  _|_  |_____|_|_|_|___|___|_,_|
|_| |___|                        

```

# pywinbox

A MikroTik's Winbox protocol honeypot. `pywinbox` parses and understands Winbox communications log them and answer to them working as a **medium interaction honeypot** or work as a **proxy** to forward them to a real/virtualized system to.

`pywinbox` also includes a MNDP (MikroTik Neighbor Discovery Protocol) script to broadcast its presence in a network. Winbox application uses this protocol to find MikroTik servers in the network.

# Behavior detection
`pywinbox` uses a set of simple rules to detect suspicious behavior or vulnerabilities exploitation. Current existing detections:
- CVE-2018-14847
- CVE-2019-3943

# Pywinbox Server

Launch `pywinbox` as a medium interaction honeypot:

`python3 pywinboxserver.py`

# Pywinbox Proxy

Launch `pywinbox` as a proxy pointing to a real/virtualized MikroTik server:

`python3 pywinboxproxy.py`

# Configuration file

To set the different parameters for both server and proxy, change the next values in the different configuration sections.

### shared
Configuration parameters used by both server and proxy.
- `users_file`: Path pointing to the desired `user.dat` file that contains the users credentials to be stolen by the attackers.
- `dump_folder`: Folder to dump oll the conenctions for later analysis.
- `protocols`: Enabled protocols. Current available protocols are `plaintext` and `ecsrp5`.

```yaml
[shared]
users_file=/data/user.dat
dump_folder=/data/pywinbox/dumps
protocols=plaintext,ecsrp5
```

### proxy
Configuration parameters used only by the proxy functionality:
- `host`: IP address to listen to.
- `port`: TCP port to listen to.
- `upstream_host`: IP address of the server to forward the connections to.
- `upstream_port`: TCP port where the real server is listening to.
- `ecsrp5_user`: Username used to log into the upstream server if ECSRP5 protocol is used.
- `ecsrp5_password`: Password used to log into the upstream server if ECSRP5 protocol is used.

```yaml
[proxy]
host=192.168.1.3
port=8291
upstream_host=10.10.1.1
upstream_port=8291
ecsrp5_user=admin
# leave ecsrp5_password empty for default empty password
ecsrp5_password=
```

### server
Configuration parameters used only by the server functionality:
- `host`: IP address to listen to.
- `port`: TCP port to listen to.
```yaml
[server]
host=192.168.1.3
port=8291
```

### logger
Confiuration parameters to set how the information is logged
- `console`: Print log informatin in the conosole
- `colored`: If `console=yes`, then print the log information with different colors depending on the printed message.
- `indent`: Integer to set the number of spaces to indent the JSON lines. Leave it blank to avoid identation.
- `file`: Log file path. Leave it blank if you don't want to log in a file.

```yaml
[logger]
colored=no
indent=
console=no
file=/var/log/pywinbox.log
``````

### mndp
Configuration parameters used by the MNDP script to broadcast its presence as MikroTik server does.
- `mac`: Set a specific MAC address. If this parameter is commented, a random MAC address is generated.
- `mac_oui`: Commeented by default. Uncomment this to use a predefined OUI and a random NIC.
- `identity`: Set the `identity` parameter.
- `version`: Set the `version` parameter.
- `platform`: Set the `platform` parameter.
- `software_id`: Set the `software_id` parameter. If this is commented, a random `software_id` is generated.
- `board`:xSet the `board` parameter.
```yaml
[mndp]
# Comment mac to generate a random MAC address
#mac=SE:TM:AC:AD:DR:ES
# Uncomment mac_oui to use a predefined OUI and a random NIC
#mac_oui=00:11:22
identity=MikroTik
version=6.40.1 (stable)
platform=MikroTik
# Comment software_id to generate a random ID
#software_id=ABCD-1234
board=x86
```

# Acknoledgements

- https://github.com/tenable/routeros/blob/master/poc/bytheway/README.md
- https://www.zscaler.es/blogs/security-research/glupteba-campaign-exploits-mikrotik-routers-still-large
- https://github.com/MarginResearch/mikrotik_authentication
- https://margin.re/2022/02/mikrotik-authentication-revealed/
- https://margin.re/content/files/2022/11/Pulling_MikroTik_into_the_Limelight-RECon-2022.pdf
- https://kirils.org/slides/2017-09-15_prez_15_MT_Balccon_pub.pdf
