all: scr example

scr:
	./setup_env.sh

run: ttp server client

run2 : example

example:
	python3 tls_client.py

ttp:
	nohup python3 my_ttp.py &

client:
	python3 my_client.py

server:
	nohup python3 my_server.py &

clear:
	rm -f ./OUTPUT/*.txt

