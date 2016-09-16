import re, sys, os
from codecs import decode

def conv(val):
    v = val.replace(',', '').replace('0x', '').replace('u8', '')
    return decode(v, 'hex')

s = open('tests.txt').read().replace(' ', '').replace('\n', '').replace('vec!', '')
pattern = r'Test{input:\[(?P<input>[\w,\,]*)\],cost:5,salt:\[(?P<salt>[\w,\,]*)\],'\
           r'output:\[(?P<output>[\w,\,]*)\]}'
res = re.findall(pattern, s)
print('result:', res)

i = 1
l = []
prefix = sys.argv[1]
os.mkdir(prefix)
for inp, salt, out in res:
    l.append('"%d"' % (i))
    open('%s/%d.salt.bin' % (prefix, i), 'wb').write(conv(salt))
    open('%s/%d.input.bin' % (prefix, i), 'wb').write(conv(inp))
    open('%s/%d.output.bin' % (prefix, i), 'wb').write(conv(out))
    i += 1

print(', '.join(l))