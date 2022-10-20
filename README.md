# Ninebot-NextGen-Firmware
### Status: Experimental

This project is based on [Xiaomi NextGen firmware patcher](https://github.com/dnandha/firmware-patcher) and i've tried to find the equivalent assembly code & patches found for Xiaomi for Ninebot

Usage example: ```python3 patcher.py drv173.bin drv173-patched.bin sls-de,sls-eu```

Download: [Patched DRV173 with SLS (only applied patch) of 30 km/h](https://github.com/trueToastedCode/Ninebot-NextGen-Firmware/tree/main/patched/DRV173)

### Supported Scooter's
- Ninebot Max G30(D) (II)

### Supported [DRV's](https://files.scooterhacking.org/firmware/max/DRV)
- 173

### Supported Patches
SLS: Speed limit of Speed Mode
(patches limit to 30 km/h, customizable in patcher.py)
- sls-eu (Europe)
- sls-de (Germany)
- sls-us (United States)

RP: Region patch
(Disgard fourth place of real serial number and pretends it's 'S', customizable in patcher.py)
- rp (All serial numbers) [Highly experimental]

#### Offets
SLS: Speed limit of Speed Mode
- sls-eu: 0x6f2e
- sls-de: 0x6f28
- sls-us: 0x7106

RP: Region patch
- rp: 0x7ad6, 0x7b7c, 0x7b96, 0x7be2, 0x7bfa

#### IN DEVELOPMENT
- RP
