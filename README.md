# kmd-mapper
Basic DLL injector with drag‑and‑drop support.
Drop a DLL onto the exe and it will inject into `notepad.exe` by default.

CLI:
kmd-mapper.exe <dll> [proc] [--kernel]

<dll>    - dll to inject  
[proc]   - target process (default: notepad.exe)  
[--kernel] - forces kernel thread creation (broken)

Make sure the driver is loaded or it won’t work.
Use kdmapper or sign the driver.

<img width="1919" height="1025" alt="image" src="https://github.com/user-attachments/assets/33d3d077-19d5-4664-83da-f70576989a2b" />
