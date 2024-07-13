SHELL := /bin/bash

install:
		pip install -r requirements.txt

run:
		/usr/bin/python3 ${PWD}/main.py

install-cron:
		echo "0 0 * * * root /usr/bin/python3 ${PWD}/main.py" > /etc/cron.d/certbot_cron
		chmod 0644 /etc/cron.d/certbot_cron
		crontab /etc/cron.d/certbot_cron