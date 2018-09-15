SHELL := bash

.PHONY: utils sync

help:
	@echo -e "utils: ツールのインストール\nsync: rsync で isucon8 repo 配る"

utils:
	cd utils; make all

sync:
	for i in {2..3}; do rsync --exclude .git -av ~/isucon8/ isu$$i:~/isucon8/; done 

nginx-service:
	sudo ln -s /home/isucon/isucon8/nginx.service /etc/systemd/system/; \ 
	sudo ln -s /home/isucon/isucon8/nginx.service /etc/systemd/system/multi-user.target.wants/


reload-nginx:
	for i in {1..3}; do \
		ssh rsync -av /home/isucon/isucon8/isu$$i /usr/local/openresty/nginx/conf/nginx.conf; \
		ssh isu$$i sudo systemctl restart nginx; \
	done

reload-app:
	for i in {1..3}; do \
		ssh isu$$i sudo systemctl restart torb.go; \
	done
