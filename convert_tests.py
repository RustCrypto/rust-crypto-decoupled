import re, sys, os
from codecs import decode

def conv(val):
    v = val.replace(',', '').replace('0x', '').replace('u8', '')
    return decode(v, 'hex')

s = open('tests.txt').read().replace(' ', '').replace('\n', '').replace('vec!', '')
pattern = r'Test{key:\[(?P<key>[\w,\,]*)\],plaintext:\[(?P<input>[\w,\,]*)\],'\
           r'ciphertext:\[(?P<output>[\w,\,]*)\]}'
res = re.findall(pattern, s)
print('result:', res)

i = 1
l = []
prefix = sys.argv[1]
os.mkdir(prefix)
for key, inp, out in res:
    l.append('"%d"' % (i))
    open('%s/%d.key.bin' % (prefix, i), 'wb').write(conv(key))
    open('%s/%d.input.bin' % (prefix, i), 'wb').write(conv(inp))
    open('%s/%d.output.bin' % (prefix, i), 'wb').write(conv(out))
    i += 1

print(', '.join(l))