# Example BS Change Watcher Plugin
The example plugin to show of DecLib for watching artifact changes.

## Install 
```
pip3 install -e . && python3 -m dl_change_watcher --install 
```

## Usage 
Open the decompiler:
1. If you are in Ghidra, use the menu to start the BS backend first
2. Right click on any function and select the `ArtifactChangeWatcher` and start the change watcher backend
3. Change any stack variable (as an example), you should see a printout that it was changed