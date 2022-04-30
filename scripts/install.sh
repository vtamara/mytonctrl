#!/usr/bin/env bash
set -e

# Проверить sudo
if [ "$(id -u)" != "0" ]; then
	echo "Please run script as root"
	exit 1
fi

# Get arguments
config="https://ton-blockchain.github.io/global.config.json"
telemetry=true
ignore=false
dump=false
while getopts m:c:tid flag
do
	case "${flag}" in
		m) mode=${OPTARG};;
		c) config=${OPTARG};;
		t) telemetry=false;;
		i) ignore=true;;
		d) dump=true;;
	esac
done


# Проверка режима установки
if [ "${mode}" != "lite" ] && [ "${mode}" != "full" ]; then
	echo "Run script with flag '-m lite' or '-m full'"
	exit 1
fi

# Проверка мощностей
mydir=$(pwd)
if [[ $OSTYPE = openbsd* ]]; then
	cpus=`sysctl -n hw.ncpu`
	memory=`sysctl -n hw.physmem`
	user=$(ls -lh ${mydir}/${0} | cut -d ' ' -f 4)
else
	cpus=$(lscpu | grep "CPU(s)" | head -n 1 | awk '{print $2}')
	memory=$(cat /proc/meminfo | grep MemTotal | awk '{print $2}')
	user=$(ls -lh ${mydir}/${0} | cut -d ' ' -f 3)
fi
if [ "${mode}" = "lite" ] && [ "$ignore" = false ] && ([ "${cpus}" -lt 2 ] || [ "${memory}" -lt 2000000 ]); then
	echo "Insufficient resources. Requires a minimum of 2 processors and 2Gb RAM."
	exit 1
fi
if [ "${mode}" = "full" ] && [ "$ignore" = false ] && ([ "${cpus}" -lt 8 ] || [ "${memory}" -lt 8000000 ]); then
	echo "Insufficient resources. Requires a minimum of 8 processors and 8Gb RAM."
	exit 1
fi

# Цвета
COLOR='\033[92m'
ENDC='\033[0m'

# Начинаю установку mytonctrl
echo -e "${COLOR}[1/4]${ENDC} Starting installation MyTonCtrl"

# На OSX и adJ/OpenBSD нет такой директории по-умолчанию, поэтому создаем...
SOURCES_DIR=/usr/src
BIN_DIR=/usr/bin
file1=${BIN_DIR}/ton/crypto/fift
file2=${BIN_DIR}/ton/lite-client/lite-client
file3=${BIN_DIR}/ton/validator-engine-console/validator-engine-console
if [[ "$OSTYPE" =~ darwin.* ]]; then
	SOURCES_DIR=/usr/local/src
	BIN_DIR=/usr/local/bin
	mkdir -p ${SOURCES_DIR}
elif [[ $OSTYPE = openbsd* ]]; then
	SOURCES_DIR=/var/ton-work/src
	BIN_DIR=/usr/local/bin
	file1=${BIN_DIR}/fift
	file2=${BIN_DIR}/lite-client
	file3=${BIN_DIR}/validator-engine-console
fi

# Проверяю наличие компонентов TON
echo -e "${COLOR}[2/4]${ENDC} Checking for required TON components"
if [ -f "${file1}" ] && [ -f "${file2}" ] && [ -f "${file3}" ]; then
	echo "TON exist"
	mkdir -p $SOURCES_DIR
	cd $SOURCES_DIR
	rm -rf $SOURCES_DIR/mytonctrl
	git clone --recursive --branch=adJ https://github.com/vtamara/mytonctrl.git
	if [[ $OSTYPE = openbsd* ]]; then
		mkdir -p /var/ton-work/mytonctrl/
		ftp -o /var/ton-work/mytonctrl/global.config.json ${config}
	fi
elif [[ $OSTYPE = openbsd* ]]; then
	echo "In adJ/OpenBSD install the package ton-20220417 precompiled for adJ 7.1a1 or compile the port available at: https://github.com/pasosdeJesus/adJ/tree/main/arboldes/usr/ports/mystuff/net/ton"
	exit 1
else
	rm -f toninstaller.sh
	wget https://raw.githubusercontent.com/ton-blockchain/mytonctrl/master/scripts/toninstaller.sh
	bash toninstaller.sh -c ${config}
	rm -f toninstaller.sh
fi

# Запускаю установщик mytoninstaller.py
echo -e "${COLOR}[3/4]${ENDC} Launching the mytoninstaller.py with user $user"
python3 ${SOURCES_DIR}/mytonctrl/mytoninstaller.py -m ${mode} -u ${user} -t ${telemetry} --dump ${dump}

# Выход из программы
echo -e "${COLOR}[4/4]${ENDC} Mytonctrl installation completed"
if [[ $OSTYPE = openbsd* ]]; then
	echo "In your ~/.profile or ~/.zshrc.local or equivalent add:"
	echo "    export FIFTPATH=/usr/local/lib/fift/:/usr/local/share/ton/smartcont/"
fi
exit 0
