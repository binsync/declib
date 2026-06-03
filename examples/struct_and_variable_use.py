# This example works with the binary found in ../tests/binaries/fauxware
# To use this script, open that binary in a decompiler, than run this script.
from declib.api import DecompilerInterface
from declib.artifacts import Struct, StructMember

deci = DecompilerInterface.discover()
# access a function and stack variable using their offsets, which get unified across decompilers
func = deci.functions[0x71D]
stack_var = func.stack_vars[-0x18]
print("Stack variable:", stack_var)

# make a struct that is the same size as the stack variable (16)
members = {
    0: StructMember(name="field1", type_="int", size=4, offset=0),
    4: StructMember(name="field2", type_="int", size=4, offset=4),
    8: StructMember(name="field3", type_="int", size=4, offset=8),
    12: StructMember(name="field4", type_="int", size=4, offset=12),
}
struct = Struct(name="my_struct", size=16, members=members)
print("Struct:", struct)
deci.structs["my_struct"] = struct

# modify the stack variable to use the struct
stack_var.type = "my_struct"
print("Updated stack variable:", stack_var)

# reassign to affect the decompiler
deci.functions[0x71D] = func
