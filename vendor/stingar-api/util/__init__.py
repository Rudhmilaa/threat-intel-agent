# Util package for apiarist
# Import json_converter from parent util.py to maintain backward compatibility
import sys
import os
# Import from parent directory's util.py
parent_dir = os.path.dirname(os.path.dirname(__file__))
util_py_path = os.path.join(parent_dir, 'util.py')
if os.path.exists(util_py_path):
    import importlib.util
    spec = importlib.util.spec_from_file_location("util_module", util_py_path)
    util_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(util_module)
    # Export json_converter and other functions from util.py
    json_converter = util_module.json_converter
    generate_keypair = util_module.generate_keypair
    encrypt_data = util_module.encrypt_data
    decrypt_data = util_module.decrypt_data

