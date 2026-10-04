# x86RisenStartupCrashFix

An experimental patch for a Risen 1 (32-bit) startup crash in `SHW32.DLL` version 8.00.41. The analyzed dump records an access violation at `SHW32.DLL+0x29B3`: `shi_free` tries to read an inaccessible SmartHeap arena header.

The patch checks the arena header with Windows `VirtualQuery` before `shi_free` reads it. If the memory is unavailable, that free is skipped. Other frees follow the original code. This may get past the observed crash, but it does not repair the pointer that became invalid. The game may still crash elsewhere, and skipped frees can leak memory. Gameplay has not been verified.

## Use

1. Close Risen. Find `SHW32.DLL` next to `Risen.exe` in the game's `bin` folder.
2. Back up the original DLL outside `bin`.
3. Run the patch script against your own original DLL:

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File .\build-fix.ps1 -Source "C:\path\to\Risen\bin\SHW32.DLL"
   ```

4. Copy the generated `dist\SHW32.DLL` into the game's `bin` folder, replacing `SHW32.DLL`.
5. Launch the game. If it fails or behaves oddly, restore the backup.

The script accepts only the unmodified, analyzed 32-bit DLL with SHA-256 `C59315DC66BC0A21988C4AF419C213F793D3B04B4511BE136556034EFD25CC38`. It rejects a DLL that has already been patched. It writes only to `dist` and never alters the original. Steam file verification may restore the original DLL.

## Scope and licensing

This repository contains the patch script and documentation. It does **not** distribute Risen or MicroQuill SmartHeap binaries. You must use your own legitimately obtained game files. The script and documentation are MIT licensed; the original DLL remains under its own license.

The patch redirects `shi_free` through 106 bytes of unused padding in the DLL's executable section. It changes five entry-point bytes and leaves all other original code in place. The Risen executable in the analyzed dump had a different image size from the executable available for inspection, so the patch remains experimental until tested against the affected installation.
