# CONFEDSS

## **Con**colic **F**irmware **E**mulation using **D**ynamic **S**tate **S**election

CONFEDSS is a project designed for emulating low-level firmware to aid in reverse engineering and testing. Its main goal is easy emulation of firmware loaded in Ghidra, but with some distinct features.

One of the main challenges in reversing low-level firmware (e.g. bootloaders, embedded controllers and such) is the peripherals attached to a device running this firmware. These peripherals can include for example RTC's, timers, interrupt controllers, flash controllers and more. In these applications, there are often no well-defined interfaces or standards for communicating with these peripherals. Instead, raw register interfaces are used, which are usually proprietary.

This makes reverse engineering and emulating these firmwares a challenging and time-consuming task, as every peripheral read has to be manually handled to keep the emulator from crashing. CONFEDSS aims to automate the handling of these unknown peripherals, using symbolic execution with dynamic selection of several tactics to approximate valid data from the peripheral.

This system was implemented as part of a Master Thesis project. The accompanying thesis document can be found [here](https://repository.tudelft.nl/islandora/object/uuid:39456df2-06f2-4428-8417-5e11c188a60e). This document describes the workings of the CONFEDSS system on a higher level. In addition, it motivates various design decisions and describes some alternative implementations.

## Usage

### Prerequisites

* Ghidra with the [ret-sync](https://github.com/bootleg/ret-sync#ghidra-extension) plugin installed
* [Ghidra Bridge](https://pypi.org/project/ghidra-bridge/) must be installed and available in the Python environment of CONFEDSS
* GDB-multiarch with the [ret-sync](https://github.com/bootleg/ret-sync#gnu-gdb-gdb-installation) plugin loaded
* CONFEDSS with all the requirements installed (`python3 -m pip install -r requirements.txt`)

### Running

1. Start the Ghidra CodeBrowser with the firmware you want to emulate.
2. Start a [Ghidra Bridge](https://pypi.org/project/ghidra-bridge/) server in the background.
3. Start the emulator, with a command that looks somewhat like this:

        $ python3 confedss.py --hooks hooks/example_hooks.py

    The hooks file needs to be a Python3 file which contains an `insert_hooks` function, see the example.

4. Wait for the emulation server to say `Listening on 127.0.0.1:9999`.
5. Start `gdb-multiarch`.
6. Load the `ret-sync` plugin in GDB, using something like:

        (gdb) source ~/Source/ret-sync/ext_gdb/sync.py

7. Connect GDB to CONFEDSS:

        (gdb) target remote :9999

    This will take a little time.

8. Once GDB has connected, start the ret-sync listener in Ghidra.
9. Sync GDB to Ghidra using `sync` command in GDB:

        (gdb) sync

    This should connect GDB to Ghidra and set Ghidra's cursor to the entry point. If it doesn't, force a single step in GDB using:

        (gdb) si

    You can now use the [Ghidra keybindings](https://github.com/bootleg/ret-sync#ghidra-usage) for debugging in Ghidra. Information about the state of registers and memory can be retrieved from the GDB shell like you normally would.

## Entry Point

The entry point that the emulator uses can be set using the `--entry_point` command line argument. This optional argument takes either the address of the entry point, or the name of a label. If a name is given, it is looked up in the Ghidra database and its address is used. If the label cannot be found, this argument is ignored.

When this argument is not provided, the system will first look for a label named either `_entry` or `_start` (in this order). If either of those labels is found, their address is used as the entry point. Otherwise, the current cursor location in the CodeBrowser is used as the entry point.

## Hooks

Using the `--hooks` argument, you can supply the emulator with a Python file containing hooks to monitor/alter the debugged code at runtime. An example of this has is available in `hooks_example.py`. The only thing you need to define in this file is an `insert_hooks` function, which takes 2 arguments:

1. A Qiling object, representing the emulator state
2. A Ghidra object, which can be used to control the attached Ghidra instance

The Qiling object can then be used to write [Qiling hooks](https://docs.qiling.io/en/latest/hook/).

## Snapshots

To reduce loading time and length of execution, you can use Qiling's snapshotting functionality to start from a previously saved state. Just provide a snapshot file to the emulator using the `--snapshot` argument. How to make a snapshot is shown in the `create_snapshot` hook in the `hooks_example.py`.

## Memory Mappings

There might be times when you want to create extra memory mappings, but don't want to add them in Ghidra for whatever reason. For this, you can use the `--mappings` argument. To do this, create a JSON file containing a dictionary with the offset as keys and the size of the mapped region as the value. The offset needs to be a "string", because JSON doesn't allow integers as dictionary keys. An example is provided in `mappings_example.json`.

## Security

Nothing about this setup provides any guarantees about security.

For example, the format for snapshots is a [Python Pickle](https://docs.python.org/3/library/pickle.html), which, as the documentation shows, is not secure. This setup should therefore be considered for use in research purposes only, and it is advisable that a running instance is not made publicly available.
