def PLUGIN_ENTRY(*args, **kwargs):
    try:
        from declib.decompilers.ida import DecLibPlugin
    except ImportError:
        print("[!] declib is not installed, please `pip install declib` for THIS python interpreter")
        return None

    return DecLibPlugin(*args, **kwargs)
