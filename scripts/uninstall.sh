#!/usr/bin/env bash

# Проверить sudo
if [ "$(id -u)" != "0" ]; then
	echo "Please run script as root"
	exit 1
fi

# Цвета
COLOR='\033[34m'
ENDC='\033[0m'

# Остановка служб
SYSTEMCTL=systemctl
if [[ $OSTYPE = openbsd* ]]; then
	SYSTEMCTL=rcctl
fi
$SYSTEMCTL stop validator
$SYSTEMCTL stop mytoncore
$SYSTEMCTL stop dht-server

# Переменные
if [[ $OSTYPE = openbsd* ]]; then
	if [[ -f /etc/rc.d/mytoncore ]]; then
		str=$(grep servicio_user /etc/rc.d/mytoncore | cut -d '=' -f2)
		user=$(echo ${str})
	else
		user=${DOAS_USER}
	fi
else
	str=$(systemctl cat mytoncore | grep User | cut -d '=' -f2)
	user=$(echo ${str})
fi

# Удаление служб
if [[ $OSTYPE = openbsd* ]]; then
	rm -rf /etc/rc.d/validator
	rm -rf /etc/rc.d/mytoncore
	rm -rf /etc/rc.d/dht-server
else
	rm -rf /etc/systemd/system/validator.service
	rm -rf /etc/systemd/system/mytoncore.service
	rm -rf /etc/systemd/system/dht-server.service
	systemctl daemon-reload
fi

# Удаление файлов
if [[ $OSTYPE != openbsd* ]]; then
	rm -rf /var/ton-work/src
else
	rm -rf /usr/src/ton
	rm -rf /usr/src/mytonctrl
	rm -rf /usr/bin/ton
	rm -rf /usr/local/bin/mytoninstaller/
	rm -rf /usr/local/bin/mytoncore/mytoncore.db
fi
rm -rf /var/ton-work
rm -rf /var/ton-dht-server
rm -rf /tmp/myton*
rm -rf /home/${user}/.local/share/mytonctrl
rm -rf /home/${user}/.local/share/mytoncore/mytoncore.db

# Удаление ссылок
if [[ $OSTYPE = openbsd* ]]; then
	rm -rf /usr/bin/lite-client-gc
else
	rm -rf /usr/bin/fift
	rm -rf /usr/bin/liteclient
fi
rm -rf /usr/bin/validator-console
rm -rf /usr/bin/mytonctrl

# Конец
echo -e "${COLOR}Uninstall Complete${ENDC}"
