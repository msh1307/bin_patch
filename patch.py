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
f,f1=-1,-1
for i in sec:
    if b'VERNEED' in i:
        f = int(i.split()[-1],16)
    if b'.dynstr' in i:
        f1 = int(i.split()[-1],16)
assert f != -1 and f1 != -1
dynstr_off,needed_off = f1,f
assert buf[needed_off:needed_off+2]==b'\x01\x00'
off = int.from_bytes(buf[needed_off+4:needed_off+8],byteorder='little')
libc_str = (buf[dynstr_off+off:dynstr_off+off+buf[dynstr_off+off:].index(b'\x00')])
nld = b'./'+ld_str.split(b'/')[-1]
assert len(ld_str)>=len(nld)
nld,nlib = nld.ljust(len(ld_str),b'\x00'),b'./'+libc_str[2:]
print(ld_str.decode(),'|',libc_str.decode(),'->',nld.decode(),'|',nlib.decode())
ar = bytearray(buf)
for i in range(len(nld)):
    ar[i+ld_off]=nld[i]
for i in range(len(nlib)):
    ar[i+dynstr_off+off] = nlib[i]
with open('out.bin','wb') as f:
    f.write(bytes(ar))
print('Successfully patched')
