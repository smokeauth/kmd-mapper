Drag any dll into the exe and it will inject it into notepad (you can change this) and in command line you can use it like this [kmd-mapper.exe dll.dll process.exe] dll for the dll you want to inject and process for the process you want that dll to be injected inside of and add --kernel to use a different method to execute the shellcode (broken) but everything in the normal one is kernel anyway except thread creating this just forces it to create the thread in kernel (broken).

MAKE SURE TO LOAD THE DRIVER OR ELSE IT WONT WORK USE KDMAPPER OR SIGN IT.
