# Ninebot-NextGen-Firmware
### Status: Experimental
##### (99% sure everything is ok)

This project is based on [Xiaomi NextGen firmware patcher](https://github.com/dnandha/firmware-patcher) and i've tried to find the equivalent assembly code & patches found for Xiaomi for Ninebot

Usage example: ```python3 patcher.py drv173.bin drv173-patched.bin sls-de,sls-eu```

Download: [Patched DRV173 with SLS of 30 km/h](https://github.com/trueToastedCode/Ninebot-NextGen-Firmware/tree/main/patched/DRV173)

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
