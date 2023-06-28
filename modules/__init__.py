mods = []

# Funny function I stole from gallery dl
def _internal():
    import os
    import inspect
    import commons

    globals_ = globals()
    for module_name in os.listdir("modules"):
        module_name = module_name.rsplit('.', 1)[0]
        if "__init__" in module_name: continue

        module = __import__(module_name, globals_, None, (), 1)
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, commons.Module) and obj is not commons.Module:
                mods.append(obj())

_internal()