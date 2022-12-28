# CONFEDSS

## **Con**colic **F**irmware **E**mulation using **D**ynamic **S**tate **S**election

CONFEDSS is a project designed for emulating low-level firmware to aid in reverse engineering and testing. It's main goal is easy emulation of firmware loaded in Ghidra, but with some distinct features.

One of the main challenges in reversing low-level firmware (e.g. bootloaders, embedded controllers and such) is the peripherals attached to a device running this firmware. These peripherals can include for example RTC's, timers, interrupt controllers, flash controllers and more. In these applications there's often no well defined interfaces or standards for communicating with these peripherals, only raw register interfaces, which are usually proprietary. 

This makes reverse engineering these firmwares a challenging and time-consuming task, as every peripheral read has to be manually handled to keep the emulator from crashing. CONFEDSS aims to automate the handling of these unknown peripherals, using symoblic execution with dynamic selection of several tactics to approximate valid data from the peripheral.

## Usage

### Prerequisites

* Ghidra with the [ret-sync](https://github.com/bootleg/ret-sync#ghidra-extension) plugin installed
* [Ghidra Bridge](https://pypi.org/project/ghidra-bridge/) must be installed and available in the Python environment of CONFEDSS
* GDB-multiarch with the [ret-sync](https://github.com/bootleg/ret-sync#gnu-gdb-gdb-installation) plugin loaded
* CONFEDSS with all the requirements installed

### Running

1. Start the Ghidra CodeBrowser with the firmware you want to emulate. Optionally, place a label named either **_entry** or **_start** somewhere, otherwise the entry point is your current cursor location in the CodeBrowser.
2. Start a [Ghidra Bridge](https://pypi.org/project/ghidra-bridge/) server in the background.
3. Start the emulator, with a commandline that looks somewhat like this:

        $ python3 confedss.py --hooks emu_hooks.py
    The hooks file needs to be a Python3 file which contains an `insert_hooks` function, see the example.
4. Wait for the emulation server to say `Listening on 127.0.0.1:9999`.
5. Start gdb-multiarch.
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

## Hooks

Using the `--hooks` argument, you can supply the emulator with a Python file containing hooks to monitor/alter the debugged code at runtime. An example of this has is available in `hooks_example.py`. The only thing you need to define in this file is an `insert_hooks` function, which takes 2 arguments:

1. A Qiling object, representing the Qiling state
2. A Ghidra object, which can be used to control the attached Ghidra instance

The Qiling object can then be used to write [Qiling hooks](https://docs.qiling.io/en/latest/hook/).

## Snapshots

To reduce loading time and length of execution, you can use Qiling's snapshotting functionality to start from a previously saved state. Just provide a snapshot file to the emulator using the `--snapshot` argument. 

How to make a snapshot is shown in the `create_snapshot` hook in the `hooks_example.py`.

## Memory Mappings

There might be times when you want to create extra memory mappings, but don't want to add them in Ghidra for whatever reason. For this, you can use the `--mappings` argument. To do this, create a json file containing a dict with the offset as keys and the size of the mapped region as the value.

 The offset needs to be a "string", because json doesn't allow integers as dictionary keys. An example is provided in `mappings_example.json`

 ## Security

 Nothing about this setup provides any guarantees about security. 
 
 For example, the format for snapshots is a [Python Pickle](https://docs.python.org/3/library/pickle.html), which, as the documentation shows, is not secure. This setup should therefore be considered for use in research purposes only and it is advisable that a running instance is not made publicly available.
