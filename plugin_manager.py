import pluggy
from ghostcred import plugin_specs

pm = pluggy.PluginManager("ghostcred")
pm.add_hookspecs(plugin_specs)

_plugins_loaded = False

def load_plugins():
    global _plugins_loaded
    if _plugins_loaded:
        return
    _plugins_loaded = True
    
    # Load default internal implementations
    from ghostcred.scanners import patterns
    from ghostcred.revocation import default_plugins
    pm.register(patterns)
    pm.register(default_plugins)
    
    # Automatically load any plugins registered via setuptools entry points
    pm.load_setuptools_entrypoints("ghostcred")
