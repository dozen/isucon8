SHELL := bash

.PHONY: utils sync

help:
	@echo -e "utils: ツールのインストール\nsync: rsync で isucon8 repo 配る"

utils:
	cd utils; make all

sync:
	for i in {2..3}; do rsync --exclude .git -av ~/isucon8/ isu$$i:~/isucon8/; done 
