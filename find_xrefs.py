import idaapi
import idautils
import idc
import ida_kernwin

class XrefFinderPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Xref Finder Plugin"
    help = "print xrefs to and xrefs from"
    wanted_name = "Xref Finder"
    wanted_hotkey = "Ctrl-Shift-F"
    
    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        self.show_dialog()

    def term(self):
        pass

    def show_dialog(self):
        class XrefFinderForm(ida_kernwin.Form):
            def __init__(self):
                self.depth_to = 1
                self.depth_from = 1
                ida_kernwin.Form.__init__(self, r"""STARTITEM 0
BUTTON YES* OK
Xref Finder

{FormChangeCb}
<##Function name:{iFuncName}>
<##xrefs to depth:{iDepthTo}>
<##xrefs from depth:{iDepthFrom}>
""", {
                    'iFuncName': ida_kernwin.Form.StringInput(),
                    'iDepthTo': ida_kernwin.Form.NumericInput(tp=ida_kernwin.Form.FT_DEC, value=self.depth_to),
                    'iDepthFrom': ida_kernwin.Form.NumericInput(tp=ida_kernwin.Form.FT_DEC, value=self.depth_from),
                    'FormChangeCb': ida_kernwin.Form.FormChangeCb(self.OnFormChange),
                })

            def OnFormChange(self, fid):
                return 1

        form = XrefFinderForm()
        form.Compile()
        ok = form.Execute()
        if ok == 1:
            func_name = form.iFuncName.value
            depth_to = form.iDepthTo.value
            depth_from = form.iDepthFrom.value
            self.find_xrefs(func_name, depth_to, depth_from)
        form.Free()

    def find_subfunctions(self, func_name, depth, current_depth=0, path=None):
        if path is None:
            path = [func_name]
        else:
            path.append(func_name)

        if current_depth > depth:
            return

        func_ea = idc.get_name_ea_simple(func_name)
        if func_ea == idc.BADADDR:
            print(f"Function {func_name} not found.")
            return

        called_functions = set()

        for (startea, endea) in idautils.Chunks(func_ea):
            for head in idautils.Heads(startea, endea):
                if idc.is_code(idc.get_full_flags(head)):
                    refs = idautils.CodeRefsFrom(head, 0)
                    for ref in refs:
                        ref_name = idc.get_func_name(ref)
                        if not ref_name:
                            ref_name = hex(ref)
                        if ref_name and ref_name != func_name:
                            called_functions.add((ref, ref_name))

        if current_depth == depth or not called_functions:
            print(",".join(path))
        else:
            for addr, name in called_functions:
                self.find_subfunctions(name, depth, current_depth + 1, path[:])

    def find_parentfunctions(self, func_name, depth, current_depth=0, path=None):
        if path is None:
            path = [func_name]
        else:
            path.append(func_name)

        if current_depth > depth:
            return

        func_ea = idc.get_name_ea_simple(func_name)
        if func_ea == idc.BADADDR:
            print(f"Function {func_name} not found.")
            return

        calling_functions = set()

        for ref in idautils.CodeRefsTo(func_ea, 0):
            ref_name = idc.get_func_name(ref)
            if not ref_name:
                ref_name = hex(ref)
            if ref_name and ref_name != func_name:
                calling_functions.add((ref, ref_name))

        if current_depth == depth or not calling_functions:
            print(",".join(reversed(path)))
        else:
            for addr, name in calling_functions:
                self.find_parentfunctions(name, depth, current_depth + 1, path[:])

    def find_xrefs(self, func_name, depth_to, depth_from):
        self.find_parentfunctions(func_name, depth_to)
        self.find_subfunctions(func_name, depth_from)

def PLUGIN_ENTRY():
    return XrefFinderPlugin()