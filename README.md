# oG-convert
Convert nmap oG output to CSV table of just:  IP,hostname,ports

Ignores systems with no open ports in output. Takes nmap -oG output-grepable format and returns something simpler:
10.10.10.10,hostname.local,80/443/8080
