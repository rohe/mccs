import subprocess

__author__ = 'roland'

#pof = Popen(com_list, stderr=PIPE, stdout=PIPE)
pof = subprocess.Popen(['ps', "axx"], stderr=subprocess.PIPE,
                       stdout=subprocess.PIPE)

for l in pof.stdout.read().split("\n"):
    if "mccs.py" in l:
        s = l.split(" ")
        p = subprocess.Popen(["kill", "-9", s[0]])
