# Python-RE

A small Python toolkit for inspecting Windows x64 PE binaries and Unreal Engine native-function addresses. The environment is isolated from the game and project dependencies. No game executable, PAK, JMAP, credentials, or user data is included.

## Install (Windows / Python 3.12 x64)

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip check
```

`angr` requires `bitstring` and `pycparser` versions pinned in the requirements: newer versions failed at import in the tested environment. Its dependencies include Capstone, pypcode, and Z3.

## Disassemble an address

```powershell
.\.venv\Scripts\python.exe .\disassemble.py 'C:\path\to\game.exe' --rva 0x4a841a0 --size 128
```

Convert a runtime function address to an RVA by subtracting the runtime image base from the same process and dump. Do not use the preferred PE image base for this calculation when address-space layout randomization is enabled. The example RVA was observed in one test build; verify it against the exact executable and matching dump.

The command reads the executable only. It produces assembly, not recovered source code. `angr`, LIEF, iced-x86, pypcode and Unicorn are available for further scripts. Function names, structure fields, and behavior inferred from reverse engineering require separate verification.
