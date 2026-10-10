# Dual entry points share one dynamically linked runtime directory.
from pathlib import Path
from PyInstaller.utils.hooks import copy_metadata

root = Path(SPECPATH).parent
a = Analysis(
    [str(root / 'packaging/desktop_entry.py'), str(root / 'packaging/cli_entry.py')],
    pathex=[str(root / 'src')],
    datas=[(str(root / 'src/oberhau/assets'), 'oberhau/assets')]
        + copy_metadata('pydantic') + copy_metadata('PySide6-Essentials')
        + copy_metadata('tree-sitter') + copy_metadata('tree-sitter-typescript')
        + copy_metadata('tree-sitter-javascript') + copy_metadata('tree-sitter-java')
        + copy_metadata('tree-sitter-c-sharp'),
    excludes=['pytest', 'ruff', 'semgrep', 'PySide6.QtQml', 'PySide6.QtQuick',
              'PySide6.QtDesigner', 'PySide6.QtUiTools', 'PySide6.QtTest'],
)
# Qt's Windows codec imports the OS ICU API (unversioned exports). A developer's
# Git/other PATH may contain an incompatible ICU DLL with suffixed symbols; never
# redistribute that accidental selection. Windows 11 supplies the required API.
a.binaries = [entry for entry in a.binaries
              if Path(entry[0]).name.lower() != 'icuuc.dll'
              and not Path(entry[0]).name.lower().startswith('icudt')]
pyz = PYZ(a.pure)
hooks = a.scripts[:-2]
gui = EXE(pyz, hooks + a.scripts[-2:-1], [], exclude_binaries=True,
          name='Oberhau', console=False, upx=False)
cli = EXE(pyz, hooks + a.scripts[-1:], [], exclude_binaries=True,
          name='oberhau-cli', console=True, upx=False)
collect = COLLECT(gui, cli, a.binaries, a.datas, name='Oberhau', upx=False)
