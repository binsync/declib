from declib.api import DecompilerInterface

deci = DecompilerInterface.discover()
for addr, func in deci.functions.items():
    if func.size > 0x30:
        # decompile the function
        func = deci.functions[addr]
        if func.header.type == "void":
            deci.print(f"Updating {func}")
            func.header.type = "int"
            func.name = f"up_{addr}"
        # reassign to affect the decompiler
        deci.functions[addr] = func
