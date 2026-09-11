"""Read SCM directly inside the finite inventory helper, without CIM providers."""

SERVICE_SNAPSHOT = r"""
function Get-SentinelServiceSnapshot {
  if ($null -eq $script:sentinelNativeServices) {
    if (-not ('SentinelBlueNative.ServiceInventory' -as [type])) {
      Add-Type -ReferencedAssemblies System,System.Core -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace SentinelBlueNative {
  public class ServiceRecord {
    public string Name, DisplayName, State, StartMode, Status, PathName;
    public uint ExitCode;
  }
  public static class ServiceInventory {
    [StructLayout(LayoutKind.Sequential)]
    struct Status {
      public uint Type, State, Controls, ExitCode, SpecificExitCode, Checkpoint, WaitHint, ProcessId, Flags;
    }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    struct Entry {
      [MarshalAs(UnmanagedType.LPWStr)] public string Name;
      [MarshalAs(UnmanagedType.LPWStr)] public string DisplayName;
      public Status Status;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct Config {
      public uint Type, Start, ErrorControl;
      public IntPtr Binary, Group;
      public uint Tag;
      public IntPtr Dependencies, Account, DisplayName;
    }
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)]
    static extern IntPtr OpenSCManagerW(string machine,string database,uint access);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)]
    static extern IntPtr OpenServiceW(IntPtr manager,string name,uint access);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)]
    static extern bool EnumServicesStatusExW(IntPtr manager,int level,uint type,uint state,IntPtr buffer,
      uint size,out uint needed,out uint returned,ref uint resume,string group);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)]
    static extern bool QueryServiceConfigW(IntPtr service,IntPtr buffer,uint size,out uint needed);
    [DllImport("advapi32.dll",SetLastError=true)]
    static extern bool CloseServiceHandle(IntPtr handle);

    static string BoundedString(IntPtr pointer, IntPtr buffer, int size) {
      if (pointer==IntPtr.Zero) return "";
      long offset=pointer.ToInt64()-buffer.ToInt64();
      if (offset<0 || offset>=size || (offset&1)!=0) throw new InvalidOperationException("Invalid SCM string pointer");
      int capacity=(size-(int)offset)/2;
      for(int i=0;i<capacity;i++) if(Marshal.ReadInt16(pointer,i*2)==0) return Marshal.PtrToStringUni(pointer,i);
      throw new InvalidOperationException("Unterminated SCM string");
    }
    static ServiceRecord ReadOne(IntPtr manager, Entry entry) {
      IntPtr service=OpenServiceW(manager,entry.Name,1); // SERVICE_QUERY_CONFIG only
      if(service==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
      IntPtr buffer=IntPtr.Zero;
      try {
        uint needed; int size=8192;
        buffer=Marshal.AllocHGlobal(size);
        if(!QueryServiceConfigW(service,buffer,(uint)size,out needed)) {
          int error=Marshal.GetLastWin32Error();
          if(error!=122 || needed<=size || needed>65536) throw new Win32Exception(error);
          Marshal.FreeHGlobal(buffer); buffer=IntPtr.Zero; size=(int)needed;
          buffer=Marshal.AllocHGlobal(size);
          if(!QueryServiceConfigW(service,buffer,(uint)size,out needed)) throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        Config config=(Config)Marshal.PtrToStructure(buffer,typeof(Config));
        string[] states={"Unknown","Stopped","Start Pending","Stop Pending","Running","Continue Pending","Pause Pending","Paused"};
        string[] starts={"Boot","System","Auto","Manual","Disabled"};
        if(entry.Status.State<1 || entry.Status.State>=states.Length || config.Start>=starts.Length)
          throw new InvalidOperationException("Unknown SCM state or startup mode");
        if((config.Type&0x30)==0) throw new InvalidOperationException("SCM service type changed");
        return new ServiceRecord {Name=entry.Name,DisplayName=entry.DisplayName,State=states[entry.Status.State],
          Status=states[entry.Status.State],StartMode=starts[config.Start],ExitCode=entry.Status.ExitCode,
          PathName=BoundedString(config.Binary,buffer,size)};
      } finally {
        if(buffer!=IntPtr.Zero) Marshal.FreeHGlobal(buffer);
        CloseServiceHandle(service);
      }
    }
    public static ServiceRecord[] Read() {
      IntPtr manager=OpenSCManagerW(null,null,5); // CONNECT | ENUMERATE_SERVICE
      if(manager==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
      IntPtr buffer=IntPtr.Zero;
      try {
        const int size=256*1024;
        buffer=Marshal.AllocHGlobal(size);
        uint resume=0; int stride=Marshal.SizeOf(typeof(Entry));
        var rows=new List<ServiceRecord>(); var names=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for(int page=0;page<64;page++) {
          uint needed,returned,prior=resume;
          bool complete=EnumServicesStatusExW(manager,0,0x30,3,buffer,size,out needed,out returned,ref resume,null);
          int error=complete?0:Marshal.GetLastWin32Error();
          if(!complete && error!=234) throw new Win32Exception(error);
          if(returned>size/stride || rows.Count+returned>4096) throw new InvalidOperationException("SCM inventory exceeded its bound");
          for(int i=0;i<returned;i++) {
            Entry entry=(Entry)Marshal.PtrToStructure(IntPtr.Add(buffer,i*stride),typeof(Entry));
            if(String.IsNullOrEmpty(entry.Name) || entry.Name.Length>256 || !names.Add(entry.Name))
              throw new InvalidOperationException("Missing or duplicate SCM service identity");
            rows.Add(ReadOne(manager,entry));
          }
          if(complete) {
            if(rows.Count==0) throw new InvalidOperationException("SCM returned no services");
            return rows.ToArray();
          }
          if(returned==0 || resume==prior) throw new InvalidOperationException("SCM enumeration made no progress");
        }
        throw new InvalidOperationException("SCM enumeration exceeded its page bound");
      } finally {
        if(buffer!=IntPtr.Zero) Marshal.FreeHGlobal(buffer);
        CloseServiceHandle(manager);
      }
    }
  }
}
'@
    }
    # The assignment commits only a complete native result. This script scope
    # is explicitly cleared before and after every reusable-host request.
    $script:sentinelNativeServices = @([SentinelBlueNative.ServiceInventory]::Read())
  }
  $script:sentinelNativeServices
}
"""
