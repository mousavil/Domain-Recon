# import subprocess
# import re
# subfinder = subprocess.Popen("echo 'hi1' && echo 'hi2'",shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
# out, err = subfinder.communicate()
# print(out.decode('utf-8').split('\n'))
# for line in out.decode('utf-8').split('\n'):
#     print(line)

# class Domain(object):
#     def __init__(self):
#         self.name = ''
#         
# domain=domain().name='sd'
# print(domain.name)

from multiprocessing import Process
processes=[]

def printf(name):
    print(name)

def add_process(function,domain):
    proc = Process(target=function, args=(domain,))
    processes.append(proc)
    proc.start()

if __name__ == '__main__':
    add_process(printf,'hi1')
    add_process(printf,'hi2')
    add_process(printf,'hi3')