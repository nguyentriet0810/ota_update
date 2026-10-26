"""Initial serial provisioning only. Normal updates must use Wi-Fi/HTTPS OTA."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', default='COM13')
    parser.add_argument('--baud', type=int, default=921600)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--backup', type=Path, required=True)
    parser.add_argument('--backup-sha256', required=True)
    parser.add_argument('--erase-new-layout', action='store_true', required=True)
    args = parser.parse_args()
    build = args.build.resolve()
    backup = args.backup.read_bytes()
    if len(backup) != 16 * 1024 * 1024 or hashlib.sha256(backup).hexdigest() != args.backup_sha256:
        parser.error('Original full Flash backup length/digest must match before erasing')
    config = (build / 'sdkconfig').read_text(encoding='utf-8')
    for option in ('BOOTLOADER_APP_ROLLBACK_ENABLE', 'SECURE_SIGNED_APPS_NO_SECURE_BOOT',
                   'SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT', 'SPIRAM'):
        if f'CONFIG_{option}=y' not in config.splitlines():
            parser.error(f'Required profile option absent: {option}')
    for option in ('SECURE_BOOT', 'SECURE_FLASH_ENC_ENABLED', 'BOOTLOADER_APP_ANTI_ROLLBACK'):
        if f'CONFIG_{option}=y' in config.splitlines():
            parser.error(f'Hardware security must remain disabled: {option}')
    flash = json.loads((build / 'flasher_args.json').read_text())
    offsets = {int(offset, 0) for offset in flash['flash_files']}
    if not {0, 0x8000, 0x20000}.issubset(offsets):
        parser.error('Unexpected baseline bootloader/table/app offsets')
    for filename in flash['flash_files'].values():
        if not (build / filename).is_file():
            parser.error(f'Missing flash artifact: {filename}')
    base = [sys.executable, '-m', 'esptool', '--chip', 'esp32s3', '--port', args.port,
            '--baud', str(args.baud)]
    print('Backup and generated configuration verified. Initial provisioning will replace Flash contents.', flush=True)
    subprocess.run(base + ['erase-flash'], cwd=build, check=True)
    subprocess.run(base + ['write-flash', '@flash_args'], cwd=build, check=True)
    print('Initial provisioning finished; capture runtime evidence and seed baseline VALID next.', flush=True)


if __name__ == '__main__':
    main()
