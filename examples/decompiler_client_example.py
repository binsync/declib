#!/usr/bin/env python3
"""
Example demonstrating the RPyC-based DecompilerClient.

This script shows how to use the new RPyC DecompilerClient which provides
identical API to DecompilerInterface but connects to a remote server.
"""

import logging
import time
import sys
from typing import Optional

# Set up logging
logging.basicConfig(level=logging.INFO)

def example_with_local_decompiler():
    """Example using local DecompilerInterface"""
    try:
        from declib.api import DecompilerInterface
        
        print("=== Using Local DecompilerInterface ===")
        deci = DecompilerInterface.discover()
        if deci is None:
            print("No local decompiler found")
            return
        
        demo_decompiler_operations(deci)
        
    except Exception as e:
        print(f"Local decompiler error: {e}")


def example_with_remote_decompiler(server_url: str = "rpyc://localhost:18861"):
    """Example using remote DecompilerClient"""
    try:
        from declib.api.decompiler_client import DecompilerClient
        
        print(f"\n=== Using Remote DecompilerClient ({server_url}) ===")
        with DecompilerClient.discover(server_url=server_url) as deci:
            demo_decompiler_operations(deci)
            
    except Exception as e:
        print(f"Remote decompiler error: {e}")
        print("Make sure to start the server first with: declib --server")


def demo_decompiler_operations(deci):
    """
    Demo function that works identically with both DecompilerInterface and DecompilerClient.
    
    This shows the power of the unified API - the same code works regardless of whether
    the decompiler is local or remote.
    """
    print(f"Decompiler: {deci.name}")
    print(f"Binary path: {deci.binary_path}")
    print(f"Binary hash: {deci.binary_hash}")
    print(f"Base address: 0x{deci.binary_base_addr:x}" if deci.binary_base_addr else "None")
    print(f"Decompiler available: {deci.decompiler_available}")
    
    # Test fast collection operations (this is where RPyC shines)
    print(f"\n=== Testing Fast Collection Operations ===")
    
    # This should be fast - single bulk request for all light artifacts
    start_time = time.time()
    functions = list(deci.functions.items())
    end_time = time.time()
    print(f"Retrieved {len(functions)} functions in {end_time - start_time:.3f}s")
    
    # Test other collections
    collections = [
        ("comments", deci.comments),
        ("patches", deci.patches), 
        ("global_vars", deci.global_vars),
        ("structs", deci.structs),
        ("enums", deci.enums),
        ("typedefs", deci.typedefs)
    ]
    
    for name, collection in collections:
        start_time = time.time()
        items = list(collection.keys())
        end_time = time.time()
        print(f"  {name}: {len(items)} items in {end_time - start_time:.3f}s")
    
    # Test function access (if any functions exist)
    if len(deci.functions) > 0:
        print(f"\n=== Testing Individual Access ===")
        first_addr = functions[0][0]
        
        # Test full artifact access via __getitem__ (standard behavior)
        start_time = time.time()
        full_func = deci.functions[first_addr]  # This gets the full artifact
        end_time = time.time()
        print(f"Full artifact access via []: {end_time - start_time:.3f}s")
        print(f"Function: {full_func.name} at 0x{full_func.addr:x} (size: {full_func.size})")
        
        # Test light artifact access (fast, cached)
        if hasattr(deci.functions, 'get_light'):
            start_time = time.time()
            light_func = deci.functions.get_light(first_addr)
            end_time = time.time()
            print(f"Light artifact access via get_light(): {end_time - start_time:.6f}s")
        
        # Show first few functions
        print("\nFirst 5 functions:")
        for addr, func in functions[:5]:
            print(f"  0x{addr:x}: {func.name} (size: {func.size})")
    
    # Test method calls
    try:
        print(f"\n=== Testing Method Calls ===")
        if len(deci.functions) > 0:
            first_addr = list(deci.functions.keys())[0]
            light_func = deci.fast_get_function(first_addr)
            if light_func:
                print(f"  fast_get_function(0x{first_addr:x}): {light_func.name}")
            
            func_size = deci.get_func_size(first_addr)
            print(f"  get_func_size(0x{first_addr:x}): {func_size}")
            
            # Test decompilation if available
            if deci.decompiler_available:
                start_time = time.time()
                decomp = deci.decompile(first_addr)
                end_time = time.time()
                if decomp:
                    lines = decomp.text.split('\n')
                    print(f"  decompile(0x{first_addr:x}): {len(lines)} lines in {end_time - start_time:.3f}s")
                    print(f"  First line: {lines[0][:80]}...")
        else:
            print("  No functions available for testing")
            
    except Exception as e:
        print(f"  Method call error: {e}")


def discover_decompiler(prefer_remote: bool = False, server_url: str = "rpyc://localhost:18861"):
    """
    Smart discovery function that tries remote first if preferred, then falls back to local.
    
    This demonstrates how you can write code that seamlessly works with either
    local or remote decompilers based on availability.
    """
    if prefer_remote:
        # Try remote first
        try:
            from declib.api.decompiler_client import DecompilerClient
            return DecompilerClient.discover(server_url=server_url)
        except Exception:
            pass
        
        # Fall back to local
        try:
            from declib.api import DecompilerInterface
            return DecompilerInterface.discover()
        except Exception:
            return None
    else:
        # Try local first
        try:
            from declib.api import DecompilerInterface
            return DecompilerInterface.discover()
        except Exception:
            pass
        
        # Fall back to remote
        try:
            from declib.api.decompiler_client import DecompilerClient
            return DecompilerClient.discover(server_url=server_url)
        except Exception:
            return None


def main():
    if len(sys.argv) > 1:
        server_url = sys.argv[1]
    else:
        server_url = "rpyc://localhost:18861"
    
    print("DecLib DecompilerClient Example")
    print("==============================")
    
    # Demo 1: Try local decompiler
    example_with_local_decompiler()
    
    # Demo 2: Try remote decompiler
    example_with_remote_decompiler(server_url)
    
    # Demo 3: Smart discovery
    print(f"\n=== Smart Discovery (prefer remote) ===")
    deci = discover_decompiler(prefer_remote=True, server_url=server_url)
    if deci:
        print(f"Discovered: {type(deci).__name__}")
        demo_decompiler_operations(deci)
        if hasattr(deci, 'shutdown'):
            deci.shutdown()
    else:
        print("No decompiler available (local or remote)")
    
    print(f"\n=== Smart Discovery (prefer local) ===")
    deci = discover_decompiler(prefer_remote=False, server_url=server_url)
    if deci:
        print(f"Discovered: {type(deci).__name__}")
        demo_decompiler_operations(deci)
        if hasattr(deci, 'shutdown'):
            deci.shutdown()
    else:
        print("No decompiler available (local or remote)")


if __name__ == "__main__":
    main()