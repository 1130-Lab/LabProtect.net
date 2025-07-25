﻿using System.Diagnostics;
using System.Management;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using static AntiCrack_DotNet.Structs;

namespace AntiCrack_DotNet
{
    public sealed class AntiDebug
    {
        #region WinApi

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern bool SetHandleInformation(IntPtr hObject, uint dwMask, uint dwFlags);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern bool NtClose(IntPtr Handle);

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern IntPtr CreateMutexA(IntPtr lpMutexAttributes, bool bInitialOwner, string lpName);

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern bool IsDebuggerPresent();

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lib);

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr ModuleHandle, string Function);

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(SafeHandle hProcess, IntPtr BaseAddress, byte[] Buffer, uint size, int NumOfBytes);

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(SafeHandle hProcess, IntPtr BaseAddress, out byte[] Buffer, uint size, out int NumOfBytes);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtSetInformationThread(IntPtr ThreadHandle, uint ThreadInformationClass, IntPtr ThreadInformation, int ThreadInformationLength);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtOpenThread(out IntPtr hThread, uint dwDesiredAccess, ref OBJECT_ATTRIBUTES ObjectAttributes, ref CLIENT_ID ClientID);

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern uint GetTickCount();

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern IntPtr GetCurrentThread();

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern bool NtGetContextThread(IntPtr hThread, ref CONTEXT Context);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtQueryInformationProcess(IntPtr hProcess, uint ProcessInfoClass, out uint ProcessInfo, uint nSize, uint ReturnLength);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtQueryInformationProcess(IntPtr hProcess, uint ProcessInfoClass, out IntPtr ProcessInfo, uint nSize, uint ReturnLength);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtQueryInformationProcess(IntPtr hProcess, uint ProcessInfoClass, ref PROCESS_BASIC_INFORMATION ProcessInfo, uint nSize, uint ReturnLength);

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern int QueryFullProcessImageNameA(SafeHandle hProcess, uint Flags, byte[] lpExeName, Int32[] lpdwSize);

        [DllImport("win32u.dll", SetLastError = true)]
        private static extern IntPtr NtUserGetForegroundWindow();

        [DllImport("user32.dll", SetLastError = true)]
        private static extern int GetWindowTextLengthA(IntPtr HWND);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern int GetWindowTextA(IntPtr HWND, StringBuilder WindowText, int nMaxCount);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtSetDebugFilterState(ulong ComponentId, uint Level, bool State);

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern IntPtr memset(IntPtr Dst, int val, uint size);

        [DllImport("kernelbase.dll", SetLastError = true)]
        private static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, uint dwFreeType);

        [DllImport("kernel32.dll")]
        private static extern int GetLastError();

        #endregion

        /// <summary>
        /// Attempts to close an invalid handle to detect debugger presence.
        /// <param name="Syscall">specifies if we should use syscall to call the WinAPI functions.</param>
        /// </summary>
        /// <returns>Returns true if an exception is caught, indicating no debugger, otherwise false.</returns>
        public static bool NtCloseAntiDebug_InvalidHandle(bool Syscall)
        {
            try
            {
                int RandomInt = new Random().Next(int.MinValue, int.MaxValue);
                IntPtr RandomIntPtr = new IntPtr(RandomInt);
                if (Syscall)
                    Syscalls.SyscallNtClose(RandomIntPtr);
                else
                    NtClose(RandomIntPtr);
                return false;
            }
            catch
            {
                return true;
            }
        }

        /// <summary>
        /// Attempts to close a protected handle to detect debugger presence.
        /// <param name="Syscall">specifies if we should use syscall to call the WinAPI functions.</param>
        /// </summary>
        /// <returns>Returns true if an exception is caught, indicating no debugger, otherwise false.</returns>
        public static bool NtCloseAntiDebug_ProtectedHandle(bool Syscall)
        {
            string RandomMutexName = new Random().Next(int.MinValue, int.MaxValue).ToString();
            IntPtr hMutex = CreateMutexA(IntPtr.Zero, false, RandomMutexName);
            uint HANDLE_FLAG_PROTECT_FROM_CLOSE = 0x00000002;
            SetHandleInformation(hMutex, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE);
            bool Result = false;
            try
            {
                if (Syscall)
                    Syscalls.SyscallNtClose(hMutex);
                else
                    NtClose(hMutex);
                Result = false;
            }
            catch
            {
                Result = true;
            }
            SetHandleInformation(hMutex, HANDLE_FLAG_PROTECT_FROM_CLOSE, 0);
            NtClose(hMutex);
            return Result;
        }

        /// <summary>
        /// Checks if a debugger is attached to the process.
        /// </summary>
        /// <returns>Returns true if a debugger is attached, otherwise false.</returns>
        public static bool DebuggerIsAttached()
        {
            return Debugger.IsAttached;
        }

        /// <summary>
        /// Checks if a debugger is present using the IsDebuggerPresent API.
        /// </summary>
        /// <returns>Returns true if a debugger is present, otherwise false.</returns>
        public static bool IsDebuggerPresentCheck()
        {
            if (IsDebuggerPresent())
                return true;
            return false;
        }

        /// <summary>
        /// Checks for the BeingDebugged flag directly.
        /// </summary>
        /// <returns>Returns true if a debugger is present, otherwise false.</returns>
        public static bool BeingDebuggedCheck()
        {
            byte[] Code = new byte[30];
            if (IntPtr.Size == 8)
                Code = new byte[] { 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x0F, 0xB6, 0x40, 0x02, 0xC3 };
            else
                Code = new byte[] { 0x64, 0xA1, 0x30, 0x00, 0x00, 0x00, 0x0F, 0xB6, 0x40, 0x02, 0xC3 };
            IntPtr BeingDebugged = Utils.AllocateCode(Code);
            if (BeingDebugged != IntPtr.Zero)
            {
                try
                {
                    Delegates.GenericInt Executed = (Delegates.GenericInt)Marshal.GetDelegateForFunctionPointer(BeingDebugged, typeof(Delegates.GenericInt));
                    int Result = Executed();
                    Utils.FreeCode(BeingDebugged);
                    if(Result == 1)
                        return true;
                }
                catch
                {
                    Utils.FreeCode(BeingDebugged);
                }
            }
            return false;
        }

        /// <summary>
        /// Checks for the NtGlobalFlag directly.
        /// </summary>
        /// <returns>Returns true if a debugger is present, otherwise false.</returns>
        public static bool NtGlobalFlagCheck()
        {
            byte[] Code = new byte[30];
            if (IntPtr.Size == 8)
                Code = new byte[] { 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x80, 0xBC, 0x00, 0x00, 0x00, 0x48, 0x83, 0xE0, 0x70, 0x48, 0x83, 0xF8, 0x70, 0x74, 0x04, 0x48, 0x31, 0xC0, 0xC3, 0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, 0xC3 };
            else
                Code = new byte[] { 0x64, 0xA1, 0x30, 0x00, 0x00, 0x00, 0x8B, 0x40, 0x68, 0x83, 0xE0, 0x70, 0x83, 0xF8, 0x70, 0x74, 0x03, 0x31, 0xC0, 0xC3, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 };
            IntPtr NtGlobalFlag = Utils.AllocateCode(Code);
            if (NtGlobalFlag != IntPtr.Zero)
            {
                try
                {
                    Delegates.GenericInt Executed = (Delegates.GenericInt)Marshal.GetDelegateForFunctionPointer(NtGlobalFlag, typeof(Delegates.GenericInt));
                    int Result = Executed();
                    Utils.FreeCode(NtGlobalFlag);
                    if (Result == 1)
                        return true;
                }
                catch
                {
                    Utils.FreeCode(NtGlobalFlag);
                }
            }
            return false;
        }

        /// <summary>
        /// Checks if the process has debug flags set using NtQueryInformationProcess
        /// <param name="Syscall">specifies if we should use syscall to call the WinAPI functions.</param>
        /// </summary>
        /// <returns>Returns true if debug flags are set, otherwise false.</returns>
        public static bool NtQueryInformationProcessCheck_ProcessDebugFlags(bool Syscall)
        {
            uint ProcessDebugFlags = 0;
            uint Class = 0x1F;
            uint Size = sizeof(uint);
            uint Result = 0;
            if (Syscall)
                Syscalls.SyscallNtQueryInformationProcess(Class, out ProcessDebugFlags, Size, out Result);
            else
                NtQueryInformationProcess(new IntPtr(-1), 0x1F, out ProcessDebugFlags, sizeof(uint), 0);
            if (ProcessDebugFlags == 0)
                return true;
            return false;
        }

        /// <summary>
        /// Checks if the process has a debug port using NtQueryInformationProcess.
        /// <param name="Syscall">specifies if we should use syscalls to call the WinAPI functions.</param>.
        /// </summary>
        /// <returns>Returns true if a debug port is detected, otherwise false.</returns>
        public static bool NtQueryInformationProcessCheck_ProcessDebugPort(bool Syscall)
        {
            uint DebuggerPresent = 0;
            uint Size = sizeof(uint);
            if (Environment.Is64BitProcess)
                Size = sizeof(uint) * 2;
            uint Result = 0;
            if(Syscall)
                Syscalls.SyscallNtQueryInformationProcess(7, out DebuggerPresent, Size, out Result);
            else
                NtQueryInformationProcess(new IntPtr(-1), 7, out DebuggerPresent, Size, 0);
            if (DebuggerPresent != 0)
                return true;
            return false;
        }

        /// <summary>
        /// Checks if the process has a debug object handle using NtQueryInformationProcess.
        /// <param name="Syscall">specifies if we should use syscall to call the WinAPI functions.</param>
        /// </summary>
        /// <returns>Returns true if a debug object handle is detected, otherwise false.</returns>
        public static bool NtQueryInformationProcessCheck_ProcessDebugObjectHandle(bool Syscall)
        {
            IntPtr hDebugObject = IntPtr.Zero;
            uint Size = sizeof(uint);
            if (Environment.Is64BitProcess)
                Size = sizeof(uint) * 2;

            if (Syscall)
                Syscalls.SyscallNtQueryInformationProcess(0x1E, out hDebugObject, Size, 0);
            else
                NtQueryInformationProcess(new IntPtr(-1), 0x1E, out hDebugObject, Size, 0);
            if (hDebugObject != IntPtr.Zero)
                return true;
            return false;
        }

        /// <summary>
        /// Patches the DbgUiRemoteBreakin and DbgBreakPoint functions to prevent debugger attachment.
        /// </summary>
        /// <returns>Returns "Success" if the patching was successful, otherwise "Failed".</returns>
        public static string AntiDebugAttach()
        {
            IntPtr NtdllModule = Utils.LowLevelGetModuleHandle("ntdll.dll");
            IntPtr DbgUiRemoteBreakinAddress = Utils.LowLevelGetProcAddress(NtdllModule, "DbgUiRemoteBreakin");
            IntPtr DbgBreakPointAddress = Utils.LowLevelGetProcAddress(NtdllModule, "DbgBreakPoint");
            byte[] Int3InvaildCode = { 0xCC };
            byte[] RetCode = { 0xC3 };
            bool Status = WriteProcessMemory(Process.GetCurrentProcess().SafeHandle, DbgUiRemoteBreakinAddress, Int3InvaildCode, 1, 0);
            bool Status2 = WriteProcessMemory(Process.GetCurrentProcess().SafeHandle, DbgBreakPointAddress, RetCode, 1, 0);
            if (Status && Status2)
                return "Success";
            return "Failed";
        }

        /// <summary>
        /// Checks for the presence of known debugger windows.
        /// Requires elevated permissions.
        /// </summary>
        /// <returns>Returns true if a known debugger window is detected, otherwise false.</returns>
        private static HashSet<string> _badWindowNames = new HashSet<string>() { "x32dbg", "x64dbg", "windbg", "ollydbg", "dnspy", "immunity debugger", "hyperdbg", "cheat engine", "cheatengine", "ida" };
        private static bool _windowAntiDebugInitialized = false;
        private static bool _windowAntiDebugEnabled = false;
        public static bool FindWindowAntiDebug()
        {
            if (OperatingSystem.IsWindows() == false)
            {
                Process[] GetProcesses = Process.GetProcesses();
                foreach (Process GetWindow in GetProcesses)
                {
                    try
                    {
                        if (GetWindow.MainWindowHandle != IntPtr.Zero)
                        {
                            string title = GetWindow.MainWindowTitle;
                            if (string.IsNullOrEmpty(title)) continue;

                            foreach (string BadWindows in _badWindowNames)
                            {
                                if (Utils.Contains(title, BadWindows))
                                {
                                    GetWindow.Kill();
                                    return true;
                                }
                            }
                        }
                    }
                    catch
                    {
                        continue;
                    }
                }
            }
            else if (OperatingSystem.IsWindows() && !_windowAntiDebugInitialized)
            {
                var startQuery = new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace");
                using var watcher = new ManagementEventWatcher(startQuery);
                watcher.EventArrived += (s, e) =>
                {
                    string processName = e.NewEvent.Properties["ProcessName"].Value.ToString();

                    foreach (string BadWindows in _badWindowNames)
                    {
                        if (Utils.Contains(processName!, BadWindows))
                        {
                            _windowAntiDebugEnabled = true;
                        }
                    }
                };
                watcher.Start();

                Process[] GetProcesses = Process.GetProcesses();
                foreach (Process getWindow in GetProcesses)
                {
                    try
                    {
                        if (getWindow.MainWindowHandle != IntPtr.Zero)
                        {
                            string title = getWindow.MainWindowTitle;
                            if (string.IsNullOrEmpty(title)) continue;

                            foreach (string BadWindows in _badWindowNames)
                            {
                                if (Utils.Contains(title, BadWindows))
                                {
                                    getWindow.Kill();
                                    _windowAntiDebugEnabled = true;
                                }
                            }
                        }
                    }
                    catch
                    {
                        continue;
                    }
                }
            }
            return _windowAntiDebugEnabled;
        }

        /// <summary>
        /// Checks if the foreground window belongs to a known debugger.
        /// </summary>
        /// <returns>Returns true if a known debugger window is detected, otherwise false.</returns>
        public static bool NtUserGetForegroundWindowAntiDebug()
        {
            string[] BadWindowNames = { "x32dbg", "x64dbg", "windbg", "ollydbg", "dnspy", "immunity debugger", "hyperdbg", "debug", "debugger", "cheat engine", "cheatengine", "ida" };
            IntPtr HWND = NtUserGetForegroundWindow();
            if (HWND != IntPtr.Zero)
            {
                int WindowLength = GetWindowTextLengthA(HWND);
                if (WindowLength != 0)
                {
                    StringBuilder WindowName = new StringBuilder(WindowLength + 1);
                    GetWindowTextA(HWND, WindowName, WindowLength + 1);
                    foreach (string BadWindows in BadWindowNames)
                    {
                        if (Utils.Contains(WindowName.ToString().ToLower(), BadWindows))
                        {
                            return true;
                        }
                    }
                }
            }
            return false;
        }

        /// <summary>
        /// Hides threads from the debugger by setting the NtSetInformationThread.
        /// </summary>
        /// <returns>Returns "Success" if the threads were hidden successfully, otherwise "Failed".</returns>
        public static string HideThreadsAntiDebug()
        {
            try
            {
                bool AnyThreadFailed = false;
                int PID = Process.GetCurrentProcess().Id;
                ProcessThreadCollection GetCurrentProcessThreads = Process.GetCurrentProcess().Threads;
                foreach (ProcessThread Threads in GetCurrentProcessThreads)
                {
                    CLIENT_ID CI = new CLIENT_ID
                    {
                        UniqueProcess = (IntPtr)PID,
                        UniqueThread = (IntPtr)Threads.Id
                    };

                    OBJECT_ATTRIBUTES Attributes = new OBJECT_ATTRIBUTES
                    {
                        Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES)),
                        RootDirectory = IntPtr.Zero,
                        ObjectName = IntPtr.Zero,
                        Attributes = 0,
                        SecurityDescriptor = IntPtr.Zero,
                        SecurityQualityOfService = IntPtr.Zero
                    };

                    IntPtr hThread = IntPtr.Zero;
                    uint Status = NtOpenThread(out hThread, 0x0020, ref Attributes, ref CI);
                    if (Status == 0 || hThread != IntPtr.Zero)
                    {
                        uint Status2 = NtSetInformationThread(hThread, 0x11, IntPtr.Zero, 0);
                        NtClose(hThread);
                        if (Status2 != 0x00000000)
                            AnyThreadFailed = true;
                    }
                }
                if (!AnyThreadFailed)
                    return "Success";
                return "Failed";
            }
            catch
            {
                return "Failed";
            }
        }

        /// <summary>
        /// Uses GetTickCount to detect debugger presence.
        /// </summary>
        /// <returns>Returns true if debugger presence is detected, otherwise false.</returns>
        public static bool GetTickCountAntiDebug()
        {
            uint Start = GetTickCount();
            Thread.Sleep(0x10);
            return (GetTickCount() - Start) > 0x10;
        }

        /// <summary>
        /// Uses OutputDebugString to detect debugger presence.
        /// </summary>
        /// <returns>Returns true if debugger presence is detected, otherwise false.</returns>
        public static bool OutputDebugStringAntiDebug()
        {
            Debugger.Log(0, null, "just testing some stuff...");
            if (Marshal.GetLastWin32Error() == 0)
                return true;
            return false;
        }

        /// <summary>
        /// Exploits a format string vulnerability in OllyDbg.
        /// </summary>
        public static void OllyDbgFormatStringExploit()
        {
            Debugger.Log(0, null, "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s");
        }

        /// <summary>
        /// Triggers a debug break to detect debugger presence.
        /// </summary>
        /// <returns>Returns true if an exception is caught, indicating no debugger, otherwise false.</returns>
        public static bool DebugBreakAntiDebug()
        {
            try
            {
                Utils.CallInternalCLRFunction("BreakInternal", typeof(Debugger), BindingFlags.NonPublic | BindingFlags.Static, null, null);
                return false;
            }
            catch
            {
                return true;
            }
        }

        private static long CONTEXT_DEBUG_REGISTERS = 0x00010000L | 0x00000010L;

        /// <summary>
        /// Detects hardware breakpoints by checking debug registers.
        /// </summary>
        /// <returns>Returns true if hardware breakpoints are detected, otherwise false.</returns>
        public static bool HardwareRegistersBreakpointsDetection()
        {
            CONTEXT Context = new CONTEXT();
            Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            int PID = Process.GetCurrentProcess().Id;
            foreach (ProcessThread Threads in Process.GetCurrentProcess().Threads)
            {
                uint THREAD_QUERY_INFORMATION = 0x0040;
                CLIENT_ID CI = new CLIENT_ID
                {
                    UniqueProcess = (IntPtr)PID,
                    UniqueThread = (IntPtr)Threads.Id
                };

                OBJECT_ATTRIBUTES Attributes = new OBJECT_ATTRIBUTES
                {
                    Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES)),
                    RootDirectory = IntPtr.Zero,
                    ObjectName = IntPtr.Zero,
                    Attributes = 0,
                    SecurityDescriptor = IntPtr.Zero,
                    SecurityQualityOfService = IntPtr.Zero
                };

                IntPtr hThread = IntPtr.Zero;
                uint Status = NtOpenThread(out hThread, THREAD_QUERY_INFORMATION, ref Attributes, ref CI);
                if (Status == 0 || hThread != IntPtr.Zero)
                {
                    if (NtGetContextThread(hThread, ref Context))
                    {
                        if ((Context.Dr1 != 0x00 || Context.Dr2 != 0x00 || Context.Dr3 != 0x00 || Context.Dr6 != 0x00 || Context.Dr7 != 0x00))
                        {
                            NtClose(hThread);
                            return true;
                        }
                    }
                    NtClose(hThread);
                }
            }
            return false;
        }

        /// <summary>
        /// Cleans the specified path by removing null characters.
        /// </summary>
        /// <param name="Path">The path to clean.</param>
        /// <returns>The cleaned path.</returns>
        private static string CleanPath(string Path)
        {
            string CleanedPath = null;
            foreach (char Null in Path)
            {
                if (Null != '\0')
                {
                    CleanedPath += Null;
                }
            }
            return CleanedPath;
        }

        /// <summary>
        /// Checks if the parent process is a debugger by querying process information.
        /// <param name="Syscall">specifies if we should use syscall to call the WinAPI functions.</param>
        /// </summary>
        /// <returns>Returns true if the parent process is a debugger, otherwise false.</returns>
        public static bool ParentProcessAntiDebug(bool Syscall)
        {
            try
            {
                PROCESS_BASIC_INFORMATION PBI = new PROCESS_BASIC_INFORMATION();
                uint ProcessBasicInformation = 0;
                uint Result = Syscall ? Syscalls.SyscallNtQueryInformationProcess(ProcessBasicInformation, ref PBI, (uint)Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)), 0) : NtQueryInformationProcess(new IntPtr(-1), ProcessBasicInformation, ref PBI, (uint)Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)), 0);
                if (Result == 0)
                {
                    int ParentPID = PBI.InheritedFromUniqueProcessId.ToInt32();
                    if (ParentPID != 0)
                    {
                        byte[] FileNameBuffer = new byte[256];
                        Int32[] Size = new Int32[256];
                        Size[0] = 256;
                        QueryFullProcessImageNameA(Process.GetProcessById(ParentPID).SafeHandle, 0, FileNameBuffer, Size);
                        string ParentFilePath = CleanPath(Encoding.UTF8.GetString(FileNameBuffer));
                        string ParentFileName = Path.GetFileName(ParentFilePath);
                        string[] Whitelisted = { "explorer.exe", "cmd.exe" };
                        foreach (string WhitelistedFileName in Whitelisted)
                        {
                            if (ParentFileName.Equals(WhitelistedFileName))
                            {
                                return false;
                            }
                        }
                        return true;
                    }
                }
            }
            catch { }
            return false;
        }

        /// <summary>
        /// Uses NtSetDebugFilterState to prevent debugging.
        /// </summary>
        /// <returns>Returns true if the filter state was set successfully, otherwise false.</returns>
        public static bool NtSetDebugFilterStateAntiDebug()
        {
            if (NtSetDebugFilterState(0, 0, true) != 0)
                return false;
            return true;
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int ExecutionDelegate();

        /// <summary>
        /// Uses page guard to detect debugger presence by executing a function pointer.
        /// </summary>
        /// <returns>Returns true if debugger presence is detected, otherwise false.</returns>
        public static bool PageGuardAntiDebug()
        {
            SYSTEM_INFO SysInfo = new SYSTEM_INFO();
            GetSystemInfo(out SysInfo);
            uint MEM_COMMIT = 0x00001000;
            uint MEM_RESERVE = 0x00002000;
            uint PAGE_EXECUTE_READWRITE = 0x40;
            uint PAGE_GUARD = 0x100;
            uint MEM_RELEASE = 0x00008000;
            IntPtr AllocatedSpace = VirtualAlloc(IntPtr.Zero, SysInfo.PageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (AllocatedSpace != IntPtr.Zero)
            {
                memset(AllocatedSpace, 1, 0xC3);
                uint OldProtect = 0;
                if (Utils.ProtectMemory(AllocatedSpace, (UIntPtr)SysInfo.PageSize, PAGE_EXECUTE_READWRITE | PAGE_GUARD, out OldProtect))
                {
                    try
                    {
                        ExecutionDelegate IsDebugged = Marshal.GetDelegateForFunctionPointer<ExecutionDelegate>(AllocatedSpace);
                        int Result = IsDebugged();
                    }
                    catch
                    {
                        VirtualFree(AllocatedSpace, SysInfo.PageSize, MEM_RELEASE);
                        return false;
                    }
                    VirtualFree(AllocatedSpace, SysInfo.PageSize, MEM_RELEASE);
                    return true;
                }
            }
            return false;
        }
    }
}