import sys
import json

import unittest

import toml
from declib.artifacts import (
    FunctionHeader, StackVariable, FunctionArgument, Function, ArtifactFormat, Struct, StructMember,
    load_many_artifacts, Artifact
)


def generate_test_funcs(func_addr):
    fh1 = FunctionHeader(name="main", addr=func_addr, type_="int *", args={
        0: FunctionArgument(offset=0, name="a1", type_="int", size=4),
        1: FunctionArgument(offset=1, name="a2", type_="long", size=8)
    })
    fh2 = FunctionHeader("binsync_main", func_addr, type_="long *", args={
        0: FunctionArgument(offset=0, name="a1", type_="int", size=4),
        1: FunctionArgument(offset=1, name="a2", type_="int", size=4)
    })

    stack_vars1 = {
        0x0: StackVariable(stack_offset=0, name="v0", type_="int", size=4, addr=func_addr),
        0x4: StackVariable(stack_offset=4, name="v4", type_="int", size=4, addr=func_addr)
    }
    stack_vars2 = {
        0x0: StackVariable(stack_offset=0, name="v0", type_="int", size=4, addr=func_addr),
        0x4: StackVariable(stack_offset=4, name="v4", type_="long", size=8, addr=func_addr),
        0x8: StackVariable(stack_offset=8, name="v8", type_="long", size=8, addr=func_addr)
    }

    func1 = Function(addr=func_addr, size=0x100, header=fh1, stack_vars=stack_vars1)
    func2 = Function(addr=func_addr, size=0x150, header=fh2, stack_vars=stack_vars2)
    return func1, func2


class TestArtifacts(unittest.TestCase):
    def test_func_diffing(self):
        # setup top
        func_addr = 0x400000
        func1, func2 = generate_test_funcs(func_addr)

        diff_dict = func1.diff(func2)
        header_diff = diff_dict["header"]
        vars_diff = diff_dict["stack_vars"]

        # size should not match
        assert func1.size != func2.size
        assert diff_dict["size"]["before"] == func1.size
        assert diff_dict["size"]["after"] == func2.size

        # names should not match
        assert header_diff["name"]["before"] == func1.name
        assert header_diff["name"]["after"] == func2.name

        # arg1 should match
        assert not header_diff["args"][0]

        # arg2 should not match
        assert header_diff["args"][1]["type"]["before"] != header_diff["args"][1]["type"]["after"]

        # v4 and v8 should differ
        offsets = [0, 4, 8]
        for off in offsets:
            var_diff = vars_diff[off]
            if off == 0:
                assert not var_diff
            if off == 0x4:
                assert var_diff["size"]["before"] != var_diff["size"]["after"]
            elif off == 0x8:
                assert var_diff["addr"]["before"] is None
                assert var_diff["addr"]["after"] == func1.addr

    def test_func_nonconflict_merge(self):
        # setup top
        func_addr = 0x400000
        fh1 = FunctionHeader(name="user1_func", addr=func_addr, type_="int *", args={})
        fh2 = FunctionHeader(name="main", addr=func_addr, type_="long *", args={})

        stack_vars1 = {
            0x0: StackVariable(stack_offset=0, name="v0", type_="int", size=4, addr=func_addr),
            0x4: StackVariable(stack_offset=4, name="my_var", type_="int", size=4, addr=func_addr)
        }
        stack_vars2 = {
            0x0: StackVariable(stack_offset=0, name="v0", type_="int", size=4, addr=func_addr),
            0x4: StackVariable(stack_offset=4, name="v4", type_="long", size=8, addr=func_addr),
            0x8: StackVariable(stack_offset=8, name="v8", type_="long", size=8, addr=func_addr)
        }

        func1 = Function(addr=func_addr, size=0x100, header=fh1, stack_vars=stack_vars1)
        func2 = Function(addr=func_addr, size=0x100, header=fh2, stack_vars=stack_vars2)
        merge_func = func1.nonconflict_merge(func2)

        assert merge_func.name == "user1_func"
        assert merge_func.header.type == "int *"
        assert merge_func.stack_vars[0].name == "v0"
        assert merge_func.stack_vars[4].name == "my_var"
        assert merge_func.stack_vars[4].type == "int"
        assert merge_func.stack_vars[8].name == "v8"

    def test_func_overwrite_merge(self):
        func_addr = 0x400000
        func_size = 0x100
        fh1 = FunctionHeader(name="main", addr=func_addr, type_="int *", args={
            0: FunctionArgument(offset=0, name="a1", type_="int", size=4)
        })
        fh2 = FunctionHeader(name="binsync_main", addr=func_addr, type_="long *", args={
            1: FunctionArgument(offset=1, name="bs_2", type_="int", size=4)
        })

        stack_vars1 = {
            0x0: StackVariable(stack_offset=0, name="v0", type_="int", size=4, addr=func_addr),
            0x4: StackVariable(stack_offset=4, name="v4", type_="long", size=8, addr=func_addr),
            0x8: StackVariable(stack_offset=8, name="v8", type_="long", size=8, addr=func_addr)
        }
        stack_vars2 = {
            0x0: StackVariable(stack_offset=0, name="v0", type_="long", size=4, addr=func_addr),
            0x4: StackVariable(stack_offset=4, name="my_var", type_="int", size=4, addr=func_addr)
        }

        func1 = Function(addr=func_addr, size=func_size, header=fh1, stack_vars=stack_vars1)
        func2 = Function(addr=func_addr, size=func_size, header=fh2, stack_vars=stack_vars2)

        merge_func = func1.overwrite_merge(func2)

        assert merge_func.size == func1.size == func2.size
        assert merge_func.name == func2.name
        assert merge_func.header.args[0].name == func1.header.args[0].name
        assert merge_func.stack_vars[0].name == stack_vars1[0].name
        assert merge_func.stack_vars[0].type == stack_vars2[0].type
        assert merge_func.stack_vars[0x4] == stack_vars2[0x4]
        assert merge_func.stack_vars[0x8] == stack_vars1[0x8]

    def test_serialization(self):
        native_load_funcs = {
            ArtifactFormat.JSON: json.loads,
            ArtifactFormat.TOML: toml.loads
        }

        func, _ = generate_test_funcs(0x400000)
        struct = Struct(name="some_struct", size=8, members={
            0: StructMember(offset=0, name="m0", type_="int", size=4),
            4: StructMember(offset=4, name="m4", type_="long", size=8)
        })
        # TODO: add comments, enums, patches, and global vars to the test
        for fmt, load_func in native_load_funcs.items():
            serialized_func = func.dumps(fmt=fmt)
            loaded_func_dict = load_func(serialized_func)

            assert loaded_func_dict["addr"] == func.addr
            assert loaded_func_dict["size"] == func.size
            assert loaded_func_dict["name"] == func.name
            assert loaded_func_dict["type"] == func.type
            assert loaded_func_dict["header"]["name"] == func.header.name
            assert loaded_func_dict["header"]["type"] == func.header.type
            assert loaded_func_dict["header"]["args"]["0x0"]["name"] == func.header.args[0].name
            # XXX: critical point: keys are strings, not integers
            assert loaded_func_dict["stack_vars"]["0x0"]["name"] == func.stack_vars[0].name

            loaded_func = Function.loads(serialized_func, fmt=fmt)
            assert loaded_func == func

            serialized_struct = struct.dumps(fmt=fmt)
            loaded_struct_dict = load_func(serialized_struct)
            assert loaded_struct_dict["name"] == struct.name
            assert loaded_struct_dict["size"] == struct.size
            assert loaded_struct_dict["members"]["0x0"]["name"] == struct.members[0].name
            assert loaded_struct_dict["members"]["0x4"]["type"] == struct.members[4].type

            loaded_struct = Struct.loads(serialized_struct, fmt=fmt)
            assert loaded_struct == struct

    def test_many_deserialization(self):
        func, _ = generate_test_funcs(0x400000)
        struct = Struct(name="some_struct", size=8, members={
            0: StructMember(offset=0, name="m0", type_="int", size=4),
            4: StructMember(offset=4, name="m4", type_="long", size=8)
        })

        # test loading many in a list of strings
        data_strs = [func.dumps(fmt=ArtifactFormat.JSON), struct.dumps(fmt=ArtifactFormat.JSON)]
        for data_str in data_strs:
            data_dict = json.loads(data_str)
            # the ART_TYPE_STR should be in the data to tell you what type of artifact it is
            assert Artifact.ART_TYPE_STR in data_dict

        loaded_arts = load_many_artifacts(data_strs, fmt=ArtifactFormat.JSON)
        assert len(loaded_arts) == 2

        loaded_func = loaded_arts[0]
        assert loaded_func == func

        loaded_struct = loaded_arts[1]
        assert loaded_struct == struct


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
