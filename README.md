# LabProtect.net
.NET Desktop application protection library. Includes all of the tricks in the AntiCrack-DotNet project as well as in-memory decryption of dependencies at runtime.

LabProtect contains a working example of Protects against debugger attachment and decompilation. 
**This is currently a research project / proof-of-concept** and I plan to extend it into a NuGet package and API for ease of use. However, I think from the simplicity of the example it can be useful for desktop app developers.

## Features
- Tricks provided by the [AntiCrack-DotNet](https://github.com/AdvDebug/AntiCrack-DotNet) project ported to .NET 8. The calling of the tricks is done via the SecureAppManager class in EncryptedApp.Common. These tricks prevent tools like dnSpy and CheatEngine from accessing and decompiling your application.
- Importing and decryption of dlls at runtime to prevent static reverse engineering such as ilSpy. Your DLLs will not be stored on disk, but you can write your code using them.
	- How it works:
		- Copy DLLs you do not wish to reside on disk to your server (in the example it's ASP.NET but could be gRPC, ZMQ or any other type of server.)
		- Delete these DLLs with a post-build event (per the example) or manually after compiling your program.
		- Request the DLLs from your client, decrypt them, and load them into your application.
		- Subscribe to the AssemblyResolve method to load decrypted assemblies.
- Further work:
	- The SecureAppChecker must be called after all assemblies are loaded, otherwise it will prevent them from being injected. This provides a window of opportunity to access the assemblies before the anti-debug tools are enabled.
		- Potentially we can call anti-inject separately from anti-debug, etc. in order to allow the injection and then, when all assemblies are loaded, enable anti-injection.
	- Many stylistic and efficiency concerns with the AntiCrack-DotNet code. Refactoring is required.
	- Create an API from this research project for ASP.NET server and Desktop client application support.
	- Generate and publish a NuGet package for ease of use and maintainability.