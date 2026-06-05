import re

line = "Jun  2 14:11:43 server sshd[1234]: Failed password for root from 192.168.1.10 port 22 ssh2"

pattern = re.compile(
    r"Failed password for (invalid user )?(\S+) from ([^\s]+)"
)

match = pattern.search(line)

print(match)
print(match.group(2))
print(match.group(3))
