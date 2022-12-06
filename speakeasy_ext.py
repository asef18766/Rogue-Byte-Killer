from speakeasy.winenv.api.usermode.msvcrt import Msvcrt
from speakeasy.windows.win32 import Win32Emulator
import speakeasy.winenv.arch as e_arch
@Msvcrt.apihook('__p___initenv', argc=0, conv=e_arch.CALL_CONV_CDECL)
def __p___initenv(self:Msvcrt, emu, argv, ctx={}):
    """char*** __p___argc ()"""
    ptr_size = self.get_ptr_size()
    env = emu.get_env()
    total = ptr_size
    sptr = total
    pptr = 0
    fmt_env = []
    for k, v in env.items():
        envstr = '%s=%s\x00' % (k, v)
        envstr = envstr.encode('utf-8')
        total += len(envstr)
        fmt_env.append(envstr)
        total += ptr_size
        sptr += ptr_size

    envp = self.mem_alloc(size=total, tag='api.envp')
    pptr = envp
    sptr += envp

    for v in fmt_env:
        self.mem_write(pptr, sptr.to_bytes(ptr_size, 'little'))
        pptr += ptr_size
        self.mem_write(sptr, v)
        sptr += len(v)

    return envp

@Msvcrt.apihook('printf', argc=1, conv=e_arch.CALL_CONV_CDECL)
def printf(self:Msvcrt, emu:Win32Emulator, argv, ctx={}):
    #TODO: implement this
    print("printf fmt:", emu.read_mem_string(argv[0]))
    return 0

# since speakeasy does not implement this well, so we have to implement our own one
@Msvcrt.apihook('__getmainargs', argc=5, conv=e_arch.CALL_CONV_CDECL)
def __getmainargs(self:Msvcrt, emu:Win32Emulator, argv, ctx={}):
    """
    int __getmainargs(
        int * _Argc,
        char *** _Argv,
        char *** _Env,
        int _DoWildCard,
        _startupinfo * _StartInfo);
    """
    # argc, argv implementation
    ptr_size = self.get_ptr_size()
    _argv = emu.get_argv()

    argv_bytes = [(a + '\x00\x00\x00\x00').encode('utf-8') for a in _argv]

    array_size = (ptr_size * (len(argv_bytes) + 1))
    total = sum([len(a) for a in argv_bytes])
    total += array_size

    sptr = 0
    pptr = 0

    arg_mem = self.mem_alloc(size=total, tag='api.argv')
    pptr = arg_mem 
    sptr = pptr + array_size

    for a in argv_bytes:
        self.mem_write(pptr, sptr.to_bytes(ptr_size, 'little'))
        pptr += ptr_size
        self.mem_write(sptr, a)
        sptr += len(a)
    self.mem_write(pptr, b'\x00' * ptr_size)
    
    self.mem_write(argv[0], len(_argv).to_bytes(ptr_size, 'little'))
    self.mem_write(argv[1], arg_mem.to_bytes(ptr_size, 'little'))

    # env implementation
    env = emu.get_env()
    total = ptr_size
    sptr = total
    pptr = 0
    fmt_env = []
    for k, v in env.items():
        envstr = '%s=%s\x00' % (k, v)
        envstr = envstr.encode('utf-8')
        total += len(envstr)
        fmt_env.append(envstr)
        total += ptr_size
        sptr += ptr_size

    envp = self.mem_alloc(size=total, tag='api.envp')
    pptr = envp
    sptr += envp

    for v in fmt_env:
        self.mem_write(pptr, sptr.to_bytes(ptr_size, 'little'))
        pptr += ptr_size
        self.mem_write(sptr, v)
        sptr += len(v)

    self.mem_write(argv[2], envp.to_bytes(ptr_size, 'little'))
    
Msvcrt.__p___initenv = __p___initenv
Msvcrt.printf = printf
Msvcrt.__getmainargs = __getmainargs