mkdir BrockAllen.IdentityReboot\lib\net45
xcopy ..\build\BrockAllen.IdentityReboot.dll BrockAllen.IdentityReboot\lib\net45 /y
xcopy ..\build\BrockAllen.IdentityReboot.pdb BrockAllen.IdentityReboot\lib\net45 /y
NuGet.exe pack BrockAllen.IdentityReboot\BrockAllen.IdentityReboot.nuspec -OutputDirectory .
