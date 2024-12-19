# Runtime-Linking

PPID-Spoofer but with runtime linking
 
## Build
```
# Build shifter.exe
gcc .\src\shifter.c -o shifter.exe -s -m64

# Build runtime_linking.exe
gcc .\src\runtime_linking.c -o runtime_linking_x64.exe -s -m64
```

## Usage
```
runtime_linking_x64.exe <Parent PID> <Executable Path> <Arguments>
```