[Данный текст доступен на русском языке.](https://github.com/ton-blockchain/mytonctrl/blob/master/README.Ru.md)

## What is it?
This console is a wrapper over `fift`,`lite-client` and `validator-engine-console`. It was created to facilitate wallet, domain and validator management on
Linux OS and adJ/OpenBSD.

![](https://raw.githubusercontent.com/ton-blockchain/mytonctrl/master/screens/mytonctrl-status.png)

## Functionality
- [x] Show TON network status
- [x] Management of local wallets
	- [x] Create local wallet
	- [x] Activate local wallet
	- [x] Show local wallets
	- [x] Import wallet from file (.pk)
	- [x] Save wallet address to file (.addr)
	- [x] Delete local wallet
- [x] Show account status
	- [x] Show account balance
	- [x] Show account history
	- [x] Show account status from bookmarks
- [x] Transferring funds to the wallet
	- [x] Transfer of a fixed amount
	- [x] Transfer of the entire amount (all)
	- [x] Transfer of the entire amount with wallet deactivation (alld)
	- [x] Transferring funds to the wallet from bookmarks
	- [x] Transferring funds to a wallet through a chain of self-deleting wallets
- [x] Manage bookmarks
	- [x] Add account to bookmarks
	- [x] Show bookmarks
	- [x] Delete bookmark
- [x] Offer management
	- [x] Show offers
	- [x] Vote for the proposal
	- [x] Automatic voting for previously voted proposals
- [x] Domain management
	- [x] Rent a new domain
	- [x] Show rented domains
	- [x] Show domain status
	- [x] Delete domain
	- [ ] Automatic domain renewal
- [x] Controlling the validator
	- [x] Participate in the election of a validator
	- [x] Return bet + reward
	- [x] Autostart validator on abnormal termination (systemd)
	- [x] Send validator statistics to https://toncenter.com

## List of tested operating systems
```
Ubuntu 16.04 LTS (Xenial Xerus) - Error: TON compilation error
Ubuntu 18.04 LTS (Bionic Beaver) - OK
Ubuntu 20.04 LTS (Focal Fossa) - OK
Debian 8 - Error: Unable to locate package libgsl-dev
Debian 9 - Error: TON compilation error
Debian 10 - OK
adJ/OpenBSD 7.1p1
```

## Installation scripts overview
- `toninstaller.sh`: clones `TON` and `mytonctrl` sources to `/usr/src/ton` and `/usr/src/mytonctrl` folders, compiles programs from sources and writes them to `/usr/bin`.
- `mytoninstaller.py`: configures the validator and `mytonctrl`; generates validator connection keys.

## Installation modes
There are two installation modes: `lite` and` full`. They both **compile** and install `TON` components if necessary. However the `lite` version does not configure or run the node/validator.


## Installation for Ubuntu
1. Download and execute the `install.sh` script in the desired installation mode. During installation the script prompts you for the superuser password several times.
   ```sh
   wget https://raw.githubusercontent.com/ton-blockchain/mytonctrl/master/scripts/install.sh
   sudo bash install.sh -m <mode>
   ```

2. Done. You can try to run the `mytonctrl` console now.
   ```sh
   mytonctrl
   ```

## Installation for Debian
1. Download and execute the `install.sh` script in the desired installation mode. During installation the script prompts you for the superuser password several times.
   ```sh
   wget https://raw.githubusercontent.com/ton-blockchain/mytonctrl/master/scripts/install.sh
   su root -c 'bash install.sh -m <mode>'
   ```

2. Done. You can try to run the `mytonctrl` console now.
   ```sh
   mytonctrl
   ```

## Installation for adJ/OpenBSD

#### Requirements and differences in paths

We suppose that you are on adJ 7.1p1 that has most of the tools required
including the following precompiled packages:

* `python-3.9*`
* `bash`
* `ton` with precompiled binaries of 
  <https://github.com/newton-blockchain/ton>. If you prefer to compile
  from sources,  use the port available at:
  <https://github.com/pasosdeJesus/adJ/tree/main/arboldes/usr/ports/mystuff/net/ton>
  This package install the tools in the standard paths of the TON's cmake:
  * `/usr/local/bin/` for binaries
  * `/usr/local/include/tonlib/` for headers
  * `/usr/local/lib/cmake/Tonlib/` for cmake
  * `/usr/local/lib/fift/` for fift functions
  * `/usr/local/lib/` for static and dynamic libraries
  * `/usr/local/share/ton/smartcon` for smart contracts

We suppose that you will do the installation with a user that:
* Use `doas` to run `scripts/install.sh`
* Will be the owner of the directories `/var/ton-work/mytonctrl`,
 `/var/ton-work/mytoncore` and `/var/ton-work/src` although the directory
 `/var/ton-work` and its other files and subdirectories will be owned by the
 `validator` account in case you install a full node.

The installation paths used are:

|Description | Ubuntu  | adJ/OpenBSD | Comment |
|---|---|---|---|
| Binaries | `/usr/bin/ton/crypto/{func,pow-miner}` | `/usr/local/bin/{fift,func,pow-miner}` | Managed with package `ton` |
| Script/Binary | `/usr/bin/fift` | `/usr/local/bin/fift` | In Linux it is a script that calls `/usr/bin/ton/crypto/fift`, in adJ is a binary managed with the package `ton` |
| Binary | `/usr/bin/ton/lite-client/lite-client` | `/usr/local/bin/lite-client` | Managed with package `ton` |
| Binary | `/usr/bin/ton/validator-engine/validator-engine` | `/usr/local/bin/validator-engine | Managed with package `ton` |
| Binary | `/usr/bin/ton/validator-engine-console/validator-engine-console` | `/usr/local/bin/validator-engine-console` | Managed with package `ton` |
| Script | `/usr/bin/lite-client` | `/usr/local/bin/lite-client-gc` | Calls the binary `lite-client` with configuration for mainnet, we renamed it because `/usr/local/bin/lite-client` is binary managed by package ton |
| Script | `/usr/bin/validator-console` | `/usr/local/bin/validator-console` | Calls `validator-engine-console` with default arguments |
| Script | `/usr/bin/mytonctrl` | `/usr/local/bin/mytonctrl` | Runs the source mytonctrl.py |
| Modification to global configuration | `/etc/environment` | None | The installer reminds the user has to add variable `FIFTPATH` to its `~/.profile` or equivalent |
| Fift libraries | `/usr/src/ton/crypto/fift/lib` | `/usr/local/lib/fift/` | Managed with package `ton` |
| Default Smart Contracts | `/usr/src/ton/crypto/smartcont` | `/usr/local/share/ton/smartcont/` | Managed with package `ton` |
| Sources | `/usr/src/` | `/var/ton-work/src` | In OpenBSD `/usr/src` is reserved for the sources of the base system |
| Configuration of mainnet | `/usr/bin/ton/global.config.json` | `/var/ton-work/mytonctrl/global.config.json` | |
| Default local configuration | `/usr/bin/ton/local.config.json` | `/var/ton-work/mytonctrl/local.config.json` | |
| `mytoncore` configuration for normal users | `~/.local/share/mytoncore/mytoncore.db` | Same | |
| `mytoncore` configuration for root user | `/usr/bin/mytoncore/mytoncore.db` | `/var/ton-work/mytoncore/mytoncore.db` | |
| `mytonctrl` configuration for normal users | `~/.local/share/mytonctrl/mytonctrl.db` | Same | |
| `mytonctrl` configuration for root user | `/usr/bin/mytonctrl/mytonctrl.db` | `/var/ton-work/mytonctrl/mytonctrl.db` | |
| Services scripts | `/etc/systemd/system/{mytoncore,validator}.service` | `/etc/rc.d/{mytoncore,validator}` | |


Before starting install the package `py3-pip3`:
```
doas pkg_add py3-pip
```
And with it install some python libraries:
```
doas pip3 install psutil crc16 requests
```

#### Installation procedure

1. Download and execute the `install.sh` script in the desired installation 
   mode. 
   ```sh
   wget https://raw.githubusercontent.com/vtamara/mytonctrl/adJ/scripts/install.sh
   doas bash install.sh -m <mode>
   ```

2. Done. You can try to run the `mytonctrl` console now.
   ```sh
   mytonctrl
   ```

If you want to uninstall what the script `scripts/install.sh` does run:
```
scripts/uninstall-adJ.sh
```

## Telemetry
By default, `mytonctrl` sends validator statistics to the https://toncenter.com server.
It is necessary to identify network abnormalities, as well as to quickly give feedback to developers.
To disable telemetry during installation, use the `-t` flag:
```sh
sudo bash install.sh -m <mode> -t
```

To disable telemetry after installation, do the following:
```sh
MyTonCtrl> set sendTelemetry false
```

## Web admin panel
To control the node/validator through the browser, you need to install an additional module:
`mytonctrl` -> `installer` -> `enable JR`

Next, you need to create a password for connection:
`mytonctrl` -> `installer` -> `setwebpass`

Ready. Now you can go to https://tonadmin.org site and log in with your credentials.
git: https://github.com/igroman787/mtc-jsonrpc

## Local copy of toncenter
To set up a local https://toncenter.com copy on your server, install an additional module:
`mytonctrl` ->` installer` -> `enable PT`

Ready. A local copy of toncenter is available at `http://<server-ip-address>:8000`
git: https://github.com/igroman787/pytonv3

## Useful links
1. https://github.com/ton-blockchain/mytonctrl/blob/master/docs/en/manual-ubuntu.md
2. https://ton.org/docs/
