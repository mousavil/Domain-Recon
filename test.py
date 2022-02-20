import subprocess
import re
subfinder = subprocess.Popen("echo 'hi1' && echo 'hi2'",shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
out, err = subfinder.communicate()
print(out.decode('utf-8').split('\n'))
for line in out.decode('utf-8').split('\n'):
    print(line)