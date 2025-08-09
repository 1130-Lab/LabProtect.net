# LabProtect.net
.NET Desktop application protection library. Includes all of the tricks in the AntiCrack-DotNet project as well as in-memory decryption of dependencies at runtime.

LabProtect contains a working example of how to protect against debugger attachment and decompilation.  
**This is currently a research project / proof-of-concept** and I plan to extend it into a NuGet package and API for ease of use. However, I think from the simplicity of the example it can be a useful resource for desktop app developers.

## Features
- Tricks provided by the [AntiCrack-DotNet](https://github.com/AdvDebug/AntiCrack-DotNet) project ported to .NET 8. The calling of the tricks is a work in progress, currently supporting AntiDebug and AntiSniff. These tricks prevent tools like dnSpy and CheatEngine from accessing and decompiling your application, and detecting if a user started a packet sniffer while your application was running.
	- I have yet to look into each trick. The first commit calls all of them, and the code is more or less left intact except for some performance enhancements. The later commits will build on a more usable interface that inherently calls each trick when the Start function is called. There is a lot to dig into in AntiCrack-DotNet.
- Importing and decryption of dlls at runtime to prevent static reverse engineering such as ilSpy. Your DLLs will not be stored on disk, but you can write your code using them.
	- How it works:
		- Copy DLLs you do not wish to reside on disk to your server (in the example it's ASP.NET but could be gRPC, ZMQ or any other type of server.)
		- Delete these DLLs with a post-build event (per the example) or manually after compiling your client application.
		- Have your client request the DLLs from your server, decrypt them, and load them into the application.
		- Subscribe to the AssemblyResolve method to load decrypted assemblies when required.
- Example of a checksum validated endpoint in order to prevent communication with a tampered executable.
    - The general workflow is as follows:
        - Create a checksum from the dlls and executable that remain in your project (i.e do not include the ones that are to be downloaded and injected)
        - Copy that executable onto your server and use it for validating that we're talking to an untampered client.
        - Wrap the encryption key with the an encryption key using the checksum.
        - When decrypting a dll on the client side, decrypt first with the checksum of the application, then with the encryption key.
	- This is still an active topic and any suggestions or feedback would be appreciated!
- Further work:
	- Stylistic and efficiency changes to the AntiCrack-DotNet code.
	- Create an API from this research project for ASP.NET server and Desktop client application support.
	- Generate and publish a NuGet package for ease of use and maintainability.
