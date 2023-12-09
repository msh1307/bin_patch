gef.py
```
 3335 def get_libc_version():
 3336             
 3337     def get_libc_version_from_path():
 3338         RE_LIBC_PATH = re.compile(r"libc6?[-_](\d+)\.(\d+)\.so")
 3339         RE_GLIBC_VERSION = re.compile(rb"glibc (\d+)\.(\d+)")                                  
 3340             
 3341         reset_gef_caches(all=True) # get_process_maps may be caching old information
 3342             
 3343         sections = get_process_maps()
 3344         for section in sections:
 3345             r = RE_LIBC_PATH.search(section.path)
 3346             if r:
 3347                 return tuple(int(x) for x in r.groups())
 3348             
 3349             if "libc" not in section.path:
 3350                 continue
 3351             
 3352             if is_container_attach():
 3353                 real_libc_path = append_proc_root(section.path)
 3354                 if not os.path.exists(real_libc_path):
 3355                     continue
 3356                 data = open(real_libc_path, "rb").read()
 3357             
 3358             elif is_remote_debug():
 3359                 if is_qemu_user():
 3360                     data = None
 3361                     for maps in get_process_maps(outer=True):
 3362                         if os.path.basename(maps.path) != os.path.basename(section.path):
 3363                             continue
 3364                         if maps.size != section.size:
 3365                             continue
 3366                         real_libc_path = maps.path
 3367                         data = open(real_libc_path, "rb").read()
 3368                         break
 3369                 else:
 3370                     data = read_remote_file(section.path)
 3371                 if not data:
 3372                     continue
 3373             else:
 3374                 if not os.path.exists(section.path):
 3375                     continue
 3376                 data = open(section.path, "rb").read()
 3377             
 3378             r = RE_GLIBC_VERSION.search(data)
 3379             if r:
 3380                 return tuple(int(x) for x in r.groups())
 3381         return None
 3382             
 3383     # use cache
```
![image](https://github.com/msh1307/init/assets/86157260/15b53bb7-0d6f-4f7f-8d8b-2bbfa345289f)

using gef, it fails to recognize glibc version after patching a binary. <br>
it requires little modification.
```
 3335 def get_libc_version():
 3336             
 3337     def get_libc_version_from_path():
 3338         RE_LIBC_PATH = re.compile(r"libc6?[-_](\d+)\.(\d+)\.so")
 3339         RE_GLIBC_VERSION = re.compile(rb"glibc (\d+)\.(\d+)")                                  
 3340             
 3341         reset_gef_caches(all=True) # get_process_maps may be caching old information
 3342             
 3343         sections = get_process_maps()
 3344         for section in sections:
 3345             r = RE_LIBC_PATH.search(section.path)
 3346             if r:
 3347                 return tuple(int(x) for x in r.groups())
 3348             
 3349             if "bc" not in section.path:
 3350                 continue
 3351             
 3352             if is_container_attach():
 3353                 real_libc_path = append_proc_root(section.path)
 3354                 if not os.path.exists(real_libc_path):
 3355                     continue
 3356                 data = open(real_libc_path, "rb").read()
 3357             
 3358             elif is_remote_debug():
 3359                 if is_qemu_user():
 3360                     data = None
 3361                     for maps in get_process_maps(outer=True):
 3362                         if os.path.basename(maps.path) != os.path.basename(section.path):
 3363                             continue
 3364                         if maps.size != section.size:
 3365                             continue
 3366                         real_libc_path = maps.path
 3367                         data = open(real_libc_path, "rb").read()
 3368                         break
 3369                 else:
 3370                     data = read_remote_file(section.path)
 3371                 if not data:
 3372                     continue
 3373             else:
 3374                 if not os.path.exists(section.path):
 3375                     continue
 3376                 data = open(section.path, "rb").read()
 3377             
 3378             r = RE_GLIBC_VERSION.search(data)
 3379             if r:
 3380                 return tuple(int(x) for x in r.groups())
 3381         return None
 3382             
 3383     # use cache
```
![image](https://github.com/msh1307/init/assets/86157260/5e5b097d-1f2d-475b-a4dc-4b1db04a1864)

gdbscript.py example
```
import gdb
gdb.execute('set debug-file-directory /ubuntu2004/lib/debug')
```
