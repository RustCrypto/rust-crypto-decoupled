import re, sys, os
from codecs import decode

s = open('tests.txt').read()
pattern = r'Test{input:"(?P<input>\w*)",output_str:"(?P<output>\w*)"}'
res = re.findall(pattern, s.replace(' ', '').replace('\n', ''))

i = 1
l = []
prefix = sys.argv[1]
os.mkdir(prefix)
for inp, out in res:
    l.append('"%s/test%d"' % (prefix, i))
    open('%s/test%d.input' % (prefix, i), 'wb').write(decode(inp, 'hex'))
    open('%s/test%d.output' % (prefix, i), 'wb').write(decode(out, 'hex'))
    i += 1

print(', '.join(l))