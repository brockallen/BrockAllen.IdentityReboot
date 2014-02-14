mkdir BrockAllen.IdentityReboot.Ef\lib\net45
xcopy ..\build\BrockAllen.IdentityReboot.Ef.dll BrockAllen.IdentityReboot.Ef\lib\net45 /y
xcopy ..\build\BrockAllen.IdentityReboot.Ef.pdb BrockAllen.IdentityReboot.Ef\lib\net45 /y
NuGet.exe pack BrockAllen.IdentityReboot.Ef\BrockAllen.IdentityReboot.Ef.nuspec -OutputDirectory .
