# DecLib Examples
This directory contains a series of example uses of DecLib in both plugins and as scripting library utilities.
When used as a plugin, DecLib requires a bit more setup to both init the UI components and start the artifact 
watching backend. 

## Plugins
### change_watcher_plugins
This plugin shows off a few things:
1. Passing a generic function to be called on Artifact changes
2. Initing a context menu in any decompiler
3. Generally setting up a plugin as a package with its own installer 