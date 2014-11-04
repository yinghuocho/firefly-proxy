# Copied from https://github.com/downloadam/client/blob/master/client/registry/win.py
import logging
import sys
import os
from contextlib import contextmanager
import subprocess

import _winreg as winreg
from _winreg import HKEY_CLASSES_ROOT, HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER, \
KEY_QUERY_VALUE, REG_SZ, KEY_ALL_ACCESS, KEY_WRITE, KEY_CREATE_SUB_KEY, KEY_SET_VALUE
 
log = logging.getLogger(__name__)
 
@contextmanager
def open_key(hkey, *args):
    key = winreg.OpenKeyEx(hkey, *args)
    yield key
    winreg.CloseKey(key)
  
@contextmanager
def create_key(hkey, subkey):
    key = winreg.CreateKey(hkey, subkey)
    yield key
    winreg.CloseKey(key)
    
def read_reg_key(hkey, subkey, name=""):
    try:
        with open_key(hkey, subkey, 0, KEY_QUERY_VALUE) as k:
            return winreg.QueryValueEx(k, name)
    except WindowsError as e:
        errno, message = e.args
        if errno != 2:
            raise e
    return (None, None)
  
def write_reg_key(hkey, subkey, name, value):
    try:
        with open_key(hkey, subkey, 0, KEY_ALL_ACCESS) as k:
            winreg.SetValueEx(k, name, 0, value[0], value[1])
            return True
    except WindowsError as e:
        errno, message = e.args
        if errno != 2:
            raise e
    return False
  
def enum_reg_keys(hkey, subkey):
    with open_key(hkey, subkey) as k:
        i = 0
        while True:
            try:
                name = winreg.EnumKey(k, i)
            except:
                break
            yield name
            i += 1

def _parse_browser_path(path):
    try:
        if path.startswith('"'):
            path = path[1:].split('"', 1)[0]
        return path
    except:
        return None

def get_default_browser():
    result = _parse_browser_path(read_reg_key(HKEY_CURRENT_USER, 'Software\\Classes\\http\\shell\\open\\command')[0])
    if result is None:
        result = _parse_browser_path(read_reg_key(HKEY_CLASSES_ROOT, 'http\\shell\\open\\command')[0])
    return result
  
def get_browser_path(key):
    result = _parse_browser_path(read_reg_key(HKEY_CURRENT_USER, 'Software\\Clients\\StartMenuInternet\\{}\\shell\\open\\command'.format(key))[0])
    if result is None:
        result = _parse_browser_path(read_reg_key(HKEY_LOCAL_MACHINE, 'Software\\Clients\\StartMenuInternet\\{}\\shell\\open\\command'.format(key))[0])
    return result
  
def iterate_browsers(default=None):
    if default is None:
        default = get_default_browser() or ''
    default = default.lower()
    ignore = set()
    for hkey in (HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE):
        try:
            enum = list(enum_reg_keys(hkey, 'Software\\Clients\\StartMenuInternet'))
        except WindowsError:
            # key not exists or something?
            continue
        for key in enum:
            if key in ignore:
                continue
            ignore.add(key)
            path = get_browser_path(key)
            if not path:
                continue
            if not os.path.exists(path):
                continue
            if key == 'IEXPLORE.EXE':
                try:
                    version = int(read_reg_key(hkey, 'Software\\Microsoft\\Internet Explorer', 'Version')[0].split('.', 1)[0])
                except AttributeError: # this maybe happens, don't know why. assume IE is outdated
                    version = 0
                if version < 9:
                    outdated = True
                else:
                    outdated = False
            elif key == 'OperaStable':
                outdated = True
            else:
                outdated = False
            yield key, path, path.lower() == default, outdated

old_ie_settings = {}

def resume_ie_settings():
    global old_ie_settings
    key = HKEY_CURRENT_USER
    subkey = 'Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'
    for (name, value) in old_ie_settings.items():
        write_reg_key(key, subkey, name, value)

def launch_ie(executable, url, rootdir, proxy_type, proxy_ip, proxy_port, default):
    global old_ie_settings
    
    key = HKEY_CURRENT_USER
    subkey = 'Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'
    new_values = {
        'ProxyEnable'   : (4, 1),
        'ProxyOverride' : (1, u'*.local;<local>'),
        'ProxyServer'   : (1, u'%s:%d' % (proxy_ip, proxy_port)),
    }
    for (name, value) in new_values.items():
        (reg_value, reg_type) = read_reg_key(key, subkey, name)
        if reg_value is not None:        
            old_ie_settings[name] = (reg_type, reg_value)
        write_reg_key(key, subkey, name, new_values[name])
    cmdline = [
        executable,
        url,
    ]
    cmdline = [s.encode(sys.getfilesystemencoding()) for s in cmdline]
    return subprocess.Popen(cmdline)

def launch_ie_tab(executable, url, rootdir, default):
    cmdline = [
        executable,
        url,
    ]
    cmdline = [s.encode(sys.getfilesystemencoding()) for s in cmdline]
    return subprocess.Popen(cmdline)
    