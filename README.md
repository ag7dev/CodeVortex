# CodeVortex 🌀

**CodeVortex** is a powerful Windows-based tool for process injection. It allows you to allocate memory in a target process and inject a copy of the current process's executable into that memory space. By utilizing direct system calls such as `NtOpenProcess`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, and `NtCreateThreadEx`, it performs seamless injection and execution of code within the remote process. This project demonstrates the use of low-level Windows APIs for effective code injection.

## Key Features 🔑

- **Process Injection**: Injects the current executable into the target process's memory.
- **Relocation Fixes**: Corrects base relocations to ensure the injected code runs as expected at a different address.
- **Remote Thread Execution**: Creates a remote thread in the target process to execute the injected code.

## Usage Instructions 🛠️

```bash
:: Start target process
start notepad

:: Inject into the process (Command Prompt)
inject.exe notepad.exe

:: Inject into the process (PowerShell)
./inject.exe notepad.exe
```

- Developed by Maggi 💻🔥

