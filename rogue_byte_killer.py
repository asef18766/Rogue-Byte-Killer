import speakeasy_ext
from speakeasy.windows.win32 import Win32Emulator
import logging
from ida_nalt import get_input_file_path
from typing import List, Tuple
import speakeasy
from ida_kernwin import Form
import idaapi
import idautils
import ida_bytes
import idc
import shlex

def get_logger():
    """
    Get the default logger for speakeasy
    """
    logger = logging.getLogger('emu_exe')
    if not logger.handlers:
        sh = logging.StreamHandler()
        logger.addHandler(sh)
        logger.setLevel(logging.DEBUG)
    return logger

emu_walked = []
def asm_hook(emu:Win32Emulator, addr, sz, ctx={}):
    global emu_walked
    print(f"addr:{sz}", hex(addr))
    emu_walked.append((addr, sz))

def get_usr_input()->Tuple[int, int, str]:
    class MyForm(Form):
        def __init__(self):
            self.invert = False
            _, sa, ea = idaapi.read_range_selection(idaapi.get_current_viewer())
            Form.__init__(
                self, 
r"""STARTITEM 0
Detection Range
<##args          :{args}>
<##start address :{start_addr}>
<##end address   :{end_addr}>
""",
                {
                    "args":Form.StringInput(),
                    "start_addr": Form.NumericInput(tp=Form.FT_ADDR, value=sa),
                    "end_addr": Form.NumericInput(tp=Form.FT_ADDR, value=ea)
                })

    form = MyForm()
    form.Compile()
    if form.Execute() == 0:
        return None, None
    return (form.start_addr.value, form.end_addr.value, form.args.value)

def get_ida_instructions(start_addr:int, end_addr:int)->List[Tuple[int, int]]:
    res = []
    for ea in idautils.Heads(start_addr, end_addr):
        insn = idaapi.insn_t()
        length = idaapi.decode_insn(insn, ea)
        res.append((ea, length))
    return res
        
def main():
    start_addr, end_addr, usr_argv = get_usr_input()
    if start_addr is None:
        return
    
    # Init the speakeasy object, an optional logger can be supplied
    print("usr argv: ", shlex.split(usr_argv))
    se = speakeasy.Speakeasy(logger=get_logger(), argv=shlex.split(usr_argv))

    # Load the module into the emulation space
    module = se.load_module(get_input_file_path())
    se.add_code_hook(asm_hook, start_addr, end_addr)
    
    # Begin emulating the EXE at its defined entry point.
    se.run_module(module)
    
    global emu_walked
    emu_walked.sort(key = lambda x:x[1], reverse=True)
    ida_ins = get_ida_instructions(start_addr, end_addr)
    
    # run checking alog
    point_list = [] 
    for a, l in ida_ins:
        point_list.append(a)
        point_list.append(a+l)
    point_list = list(set(point_list))
    
    ## check whether the begin & end exsist in ida
    ##TODO: there must an algo for O(n), but currently use O(n^2) alog
    for a, l in emu_walked:
        if a+l > end_addr or a < start_addr:
            continue
        undefind_flag = False
        h_id, e_id = 0, 0

        ### find the begin location
        if a in point_list:
            h_id = point_list.index(a)
        else:
            undefind_flag = True
            while h_id < len(point_list):
                if point_list[h_id+1] > a:
                    break
                h_id += 1
                
        ### find the ending location
        if point_list[h_id + 1] != a+l:
            undefind_flag = True
            e_id = h_id
            while e_id < len(point_list):
                e_id += 1
                if point_list[e_id] >= a+l:
                    break
        else: 
            e_id = h_id + 1
        
        if undefind_flag:
            print("=====================")
            print(f"current processing {hex(a)} to {hex(a+l)}")
            print(f"shall undefine {hex(point_list[h_id])} to {hex(point_list[e_id])}")
            print("success: ", ida_bytes.del_items(point_list[h_id], 0, point_list[e_id] - point_list[h_id]))
            print(f"new sz at {hex(a)}: ", idc.create_insn(a))

            # high light the change place
            for addr in range(point_list[h_id], point_list[e_id]):
                idc.set_color(addr, idc.CIC_ITEM, 0x0000FF)
            idc.set_color(a, idc.CIC_ITEM, 0x00FFFF)
        
if __name__ == '__main__':
    main()