# NULL Scan

sudo nmap -sN 172.20.10.3 -p 8080,9090,8000,3000,5432,5678

# XMAS Scan

sudo nmap -sX 172.20.10.3 -p 8080

# FIN Scan

sudo nmap -sF 172.20.10.3 -p 8080

# OS Fingerprinting

sudo nmap -O 172.20.10.3 -p 8080,9090,8000,3000,5432,5678

