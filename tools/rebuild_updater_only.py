"""Rebuild only the external BladeUpdater.exe from the current Blade source.

Run from the project root on Windows with activated .venv:
    python tools\\rebuild_updater_only.py
The output is outside app/ and must be copied to the test install manually.
"""
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLIENT = ROOT / 'client'
TOOLS = ROOT / 'tools'
DEST = ROOT / 'build' / 'updater_fix'


def main():
    if sys.platform != 'win32':
        raise SystemExit('Сборка BladeUpdater.exe должна выполняться в Windows')
    for p in (CLIENT / 'install_core.py', CLIENT / 'updater.py',
              CLIENT / 'config.ini', CLIENT / 'update_public.pem',
              TOOLS / 'installer_helper.py'):
        if not p.is_file():
            raise SystemExit(f'Не найден обязательный файл: {p}')
    from importlib.util import find_spec
    if find_spec('PyInstaller') is None:
        raise SystemExit('Установите PyInstaller: python -m pip install pyinstaller')
    command = [sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean',
               '--onefile', '--console', '--name', 'BladeUpdater',
               '--distpath', str(DEST / 'dist'),
               '--workpath', str(DEST / 'work'),
               '--specpath', str(DEST / 'spec'),
               '--paths', str(CLIENT)]
    for name in ('config.ini', 'update_public.pem'):
        command.extend(['--add-data', str(CLIENT / name) + os.pathsep + '.'])
    command.append(str(TOOLS / 'installer_helper.py'))
    subprocess.run(command, check=True, cwd=str(ROOT))
    result = DEST / 'dist' / 'BladeUpdater.exe'
    if not result.is_file():
        raise SystemExit('PyInstaller завершился, но BladeUpdater.exe не найден')
    print('\nГотов новый установщик:', result)
    print('Завершите Blade/BladeUpdater и скопируйте этот EXE в D:\\BladeInstallTest\\BladeUpdater.exe')
    print('НЕ копируйте его внутрь app/ и НЕ заменяйте действующий установщик во время установки.')

if __name__ == '__main__':
    main()
