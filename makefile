SHELL := /bin/bash

pwd = $(shell pwd)

install:
		pip install -r requirements.txt

run:
		/usr/bin/python3 $(pwd)/main.py

install-cron:
		echo "0 0 * * * root /usr/bin/python3 $(pwd)/main.py" > /etc/cron.d/python_certbot_acm
		chmod 0644 /etc/cron.d/python_certbot_acm
		crontab /etc/cron.d/python_certbot_acm