import sys,subprocess
args = sys.argv
with open(args[1],'rb') as f:
    buf = f.read()
assert b'ELF' in buf
res = subprocess.run(['readelf','-l',args[1]],stdout=subprocess.PIPE).stdout.split(b'\n')
f = -1
for i in res:
    if b'INTERP' in i:
        f = int(i.split()[1],16)
        break
assert f != -1
ld_str = (buf[f:f+buf[f:].index(b'\x00')])
ld_off = f
assert b'ld' in ld_str
sec = subprocess.run(['readelf','-S',args[1]],stdout=subprocess.PIPE).stdout.split(b'\n')
f1=-1
f = []
flag = 0
for i in sec:
    if b'VERNEED' in i:
        f.append(int(i.split()[-1],16))
        flag = 1
        continue
    if flag == 1:
        f.append(int(i.split()[0],16))
        flag = 0 
    if b'.dynstr' in i:
        f1 = int(i.split()[-1],16)
assert f != [] and f1 != -1

dynstr_off,verneed_off,verneed_sz = f1,f[0],f[1]
libc_str_off = -1
assert verneed_sz&0xf == 0

need_patching = []
for i in range(verneed_sz//0x10):
    tmp = buf[verneed_off+i*0x10:verneed_off+i*0x10+0x10]
    if tmp[:2] != b'\x01\x00':
        continue
    off = int.from_bytes(tmp[4:8],byteorder='little')
    t = (buf[dynstr_off+off:dynstr_off+off+buf[dynstr_off+off:].index(b'\x00')])
    need_patching.append({
        'string_offset':dynstr_off+off, 
        'string':t
    })

nld = b'./'+ld_str.split(b'/')[-1]
assert len(ld_str)>=len(nld)
nld= nld.ljust(len(ld_str),b'\x00')
print(ld_str.decode(),'->',nld.decode())
ar = bytearray(buf)
for i in range(len(nld)):
    ar[i+ld_off]=nld[i]
for i in need_patching:
    assert len(i['string']) > 2
    nn = b'./'+i['string'][2:]
    for j in range(len(nn)):
        ar[j+i['string_offset']] = nn[j]
    print(i['string'].decode(),'->',nn.decode())


    
with open('out.bin','wb') as f:
    f.write(bytes(ar))
print('Successfully patched')
print('set debug-file-directory dbgdir')
