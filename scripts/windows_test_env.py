"""Explicit environments for disposable Windows native tests.

Runtime fixtures receive only OS runtime variables and private home/temp paths.
Compiler discovery receives a separate, bounded toolchain-path allowlist.
"""
from pathlib import Path

_OS_KEYS = {key.upper(): key for key in (
    'SystemRoot', 'WINDIR', 'COMSPEC', 'PATH', 'PATHEXT', 'SystemDrive', 'OS',
    'NUMBER_OF_PROCESSORS', 'PROCESSOR_ARCHITECTURE', 'PROCESSOR_IDENTIFIER',
    'PROCESSOR_LEVEL', 'PROCESSOR_REVISION',
)}
_TOOLCHAIN_KEYS = {key.upper(): key for key in (
    'RUSTUP_HOME', 'CARGO_HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA',
    'INCLUDE', 'LIB', 'LIBPATH', 'VSINSTALLDIR', 'VCINSTALLDIR',
    'VCToolsInstallDir', 'WindowsSdkDir', 'WindowsSDKVersion',
    'UniversalCRTSdkDir', 'UCRTVersion',
)}

def _allowed(source, allowed):
    return {allowed[key.upper()]: value for key, value in source.items()
            if key.upper() in allowed}

def isolated_environment(source, private_root):
    root = Path(private_root)
    env = _allowed(source, _OS_KEYS)
    for key, name in [('HOME', 'home'), ('USERPROFILE', 'home'),
                      ('HYPERHUB_HOME', 'instance'), ('TMP', 'tmp'), ('TEMP', 'tmp'),
                      ('APPDATA', 'appdata'), ('LOCALAPPDATA', 'localappdata')]:
        env[key] = str(root / name)
    return env

def compiler_environment(source):
    return _allowed(source, {**_OS_KEYS, **_TOOLCHAIN_KEYS})
