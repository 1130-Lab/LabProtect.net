using AntiCrack_DotNet;
using EncryptedApp.Common.AntiCrack_DotNet;
using System.Reflection;

namespace EncryptedApp.Common
{
    public class SecureApplicationManager
    {
        private readonly bool IsAntiDebugChecksEnabled = true;
        private readonly bool IsAntiVirtualizationChecksEnabled = true;
        private readonly bool IsAntiInjectionEnabled = true;
        private readonly bool IsOtherDetectionChecksEnabled = true;
        private readonly bool IsAntiHookChecksEnabled = true;
        private readonly bool IsAntiSniffChecksEnabled = true;
        private readonly bool _useSysCalls;
        private readonly SemaphoreSlim _semaphore = new SemaphoreSlim(1, 1);

        public SecureApplicationManager(bool useSysCalls = false,
                                        bool isHooksEnabled = true, 
                                        bool isAntiDebugChecksEnabled = true, 
                                        bool isAntiVirtualizationChecksEnabled = true, 
                                        bool isAntiInjectionEnabled = true, 
                                        bool isOtherDetectionChecksEnabled = true, 
                                        bool isAntiHookChecksEnabled = true,
                                        bool isAntiSniffChecksEnabled = true)
        {
            _useSysCalls = useSysCalls;
            IsAntiDebugChecksEnabled = isAntiDebugChecksEnabled;
            IsAntiVirtualizationChecksEnabled = isAntiVirtualizationChecksEnabled;
            IsAntiInjectionEnabled = isAntiInjectionEnabled;
            IsOtherDetectionChecksEnabled = isOtherDetectionChecksEnabled;
            IsAntiHookChecksEnabled = isAntiHookChecksEnabled;
            IsAntiSniffChecksEnabled = isAntiSniffChecksEnabled;

            if (isHooksEnabled)
            {
                // This currently breaks the application, so it's commented out. Need to investigate further. Required a port from .NET Framework to .NET 8.
                //Hooks.PreventUnauthorizedFunctionPointerRetrieval(true, new MethodInfo[] { typeof(Utils).GetMethod("GetPointer", BindingFlags.Public | BindingFlags.Static) }, null);
            }
        }

        public async Task Run(CancellationTokenSource source)
        {
            while (!source.IsCancellationRequested)
            {
                await _semaphore.WaitAsync(source.Token);
                try
                {
                    if (IsAntiDebugChecksEnabled)
                    {
                        AntiDebugChecks();
                    }
                    if (IsAntiVirtualizationChecksEnabled)
                    {
                        AntiVirtualizationChecks();
                    }
                    if (IsAntiInjectionEnabled)
                    {
                        AntiInjectionChecks();
                    }
                    if (IsOtherDetectionChecksEnabled)
                    {
                        OtherDetectionChecks();
                    }
                    if (IsAntiHookChecksEnabled)
                    {
                        AntiHooksDetectionChecks();
                    }
                    if (IsAntiSniffChecksEnabled)
                    {
                        AntiSniffChecks();
                    }
                    await Task.Delay(500, source.Token); // Delay to avoid busy waiting
                }
                catch (OperationCanceledException)
                {
                    // Handle cancellation gracefully
                    break;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"An error occurred: {ex.Message}");
                    // Optionally log the exception or take other actions
                }
                finally
                {
                    _semaphore.Release();
                }
            }
        }

        private void AntiDebugChecks()
        {
            AntiDebug.NtUserGetForegroundWindowAntiDebug();
            AntiDebug.DebuggerIsAttached();
            AntiDebug.HideThreadsAntiDebug();
            AntiDebug.IsDebuggerPresentCheck();
            AntiDebug.BeingDebuggedCheck();
            AntiDebug.NtGlobalFlagCheck();
            AntiDebug.NtSetDebugFilterStateAntiDebug();
            AntiDebug.PageGuardAntiDebug();
            AntiDebug.HardwareRegistersBreakpointsDetection();
            AntiDebug.FindWindowAntiDebug();
            AntiDebug.NtQueryInformationProcessCheck_ProcessDebugFlags(_useSysCalls);
            AntiDebug.NtQueryInformationProcessCheck_ProcessDebugPort(_useSysCalls);
            AntiDebug.NtQueryInformationProcessCheck_ProcessDebugObjectHandle(_useSysCalls);
            AntiDebug.NtCloseAntiDebug_InvalidHandle(_useSysCalls);
            AntiDebug.NtCloseAntiDebug_ProtectedHandle(_useSysCalls);
            AntiDebug.ParentProcessAntiDebug(_useSysCalls);
        }

        private void AntiVirtualizationChecks()
        {
            AntiVirtualization.AnyRunCheck();
            AntiVirtualization.TriageCheck();
            AntiVirtualization.CheckForQemu();
            AntiVirtualization.CheckForParallels();
            AntiVirtualization.IsSandboxiePresent();
            AntiVirtualization.IsComodoSandboxPresent();
            AntiVirtualization.IsCuckooSandboxPresent();
            AntiVirtualization.IsQihoo360SandboxPresent();
            AntiVirtualization.CheckForBlacklistedNames();
            AntiVirtualization.IsWinePresent();
            AntiVirtualization.CheckForVMwareAndVirtualBox();
            AntiVirtualization.CheckForKVM();
            AntiVirtualization.CheckForHyperV();
            AntiVirtualization.BadVMFilesDetection();
            AntiVirtualization.BadVMProcessNames();
            AntiVirtualization.CheckDevices();
            AntiVirtualization.Generic.EmulationTimingCheck();
            AntiVirtualization.Generic.PortConnectionAntiVM();
            AntiVirtualization.Generic.AVXInstructions();
            AntiVirtualization.Generic.RDRANDInstruction();
            AntiVirtualization.Generic.FlagsManipulationInstructions();
        }

        private void AntiInjectionChecks()
        {
            AntiInjection.SetDllLoadPolicy();
            AntiInjection.CheckInjectedThreads(_useSysCalls, true);
            AntiInjection.ChangeModuleInfo(null, Spoofs.ModuleName | Spoofs.BaseAddress | Spoofs.AddressOfEntryPoint | Spoofs.SizeOfImage | Spoofs.ImageMagic | Spoofs.NotExecutableNorDll | Spoofs.ExecutableSectionName | Spoofs.ExecutableSectionRawSize | Spoofs.ExecutableSectionRawPointer | Spoofs.ClearExecutableSectionCharacteristics | Spoofs.ExecutableSectionVirtualSize);
            AntiInjection.ChangeCLRModuleImageMagic();
            AntiInjection.CheckForSuspiciousBaseAddress();
        }

        private void OtherDetectionChecks()
        {
            OtherChecks.IsUnsignedDriversAllowed(_useSysCalls);
            OtherChecks.IsTestSignedDriversAllowed(_useSysCalls);
            OtherChecks.IsKernelDebuggingEnabled(_useSysCalls);
            OtherChecks.IsSecureBootEnabled(_useSysCalls);
            //OtherChecks.IsVirtualizationBasedSecurityEnabled();
            OtherChecks.IsMemoryIntegrityEnabled();
            OtherChecks.IsInvokedAssembly(true);
        }

        private void AntiHooksDetectionChecks()
        {
            HooksDetection.DetectHooks();
            HooksDetection.DetectGuardPagesHooks(_useSysCalls);
            HooksDetection.DetectCLRHooks();
        }

        private void AntiSniffChecks()
        {
            AntiSniff.FindWindowAntiSniff();
        }
    }
}
