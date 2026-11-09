using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace MochaGuard
{
    internal static class ExternalGuard
    {
        // ScanProcesses used to run FileVersionInfo.GetVersionInfo() (a disk read +
        // PE resource parse) against every running process's exe, every cycle,
        // forever. Caching by pid means a still-running process only pays that cost
        // once instead of every ~5s for the whole session.
        private static readonly HashSet<uint> _checkedPids = new HashSet<uint>();

        public static void Start() { }

        public static void ScanProcesses()
        {
            try
            {
                uint currentPid = Native.GetCurrentProcessId();
                var snap = Native.CreateToolhelp32Snapshot(Native.TH32CS_SNAPPROCESS, 0);
                if (snap == IntPtr.Zero || snap == (IntPtr)(-1))
                    return;

                try
                {
                    var pe = new Native.PROCESSENTRY32();
                    pe.dwSize = (uint)Marshal.SizeOf<Native.PROCESSENTRY32>();

                    if (!Native.Process32FirstW(snap, ref pe))
                        return;

                    do
                    {
                        if (pe.th32ProcessID == currentPid)
                            continue;

                        string procName = pe.szExeFile ?? "";
                        if (string.IsNullOrEmpty(procName))
                            continue;

                        string lower = procName.ToLowerInvariant();

                        foreach (var bl in Blacklist.SuspiciousProcessNames)
                        {
                            if (lower.Contains(bl))
                            {
                                Punisher.LogWarn($"Suspicious process: {procName} pid={pe.th32ProcessID}");
                                Punisher.Kill($"proc:{procName}");
                                return;
                            }
                        }

                        bool alreadyChecked;
                        lock (_checkedPids)
                            alreadyChecked = !_checkedPids.Add(pe.th32ProcessID);
                        if (alreadyChecked)
                            continue;

                        try
                        {
                            using (var proc = Process.GetProcessById((int)pe.th32ProcessID))
                            {
                                try
                                {
                                    string mainTitle = proc.MainWindowTitle ?? "";
                                    if (!string.IsNullOrEmpty(mainTitle))
                                    {
                                        string titleLower = mainTitle.ToLowerInvariant();
                                        foreach (var kw in Blacklist.SuspiciousWindowKeywords)
                                        {
                                            if (titleLower.Contains(kw))
                                            {
                                                Punisher.LogWarn($"Suspicious window title: {mainTitle} (proc: {procName})");
                                                Punisher.Kill($"wnd:{mainTitle}");
                                                return;
                                            }
                                        }
                                    }
                                }
                                catch { }

                                try
                                {
                                    string path = "";
                                    try { path = proc.MainModule?.FileName ?? ""; } catch { }

                                    if (!string.IsNullOrEmpty(path))
                                    {
                                        var vi = FileVersionInfo.GetVersionInfo(path);
                                        string versionInfo = $"{vi.CompanyName} {vi.ProductName} {vi.FileDescription} {vi.OriginalFilename} {vi.InternalName}".ToLowerInvariant();

                                        foreach (var kw in Blacklist.SuspiciousFileVersionKeywords)
                                        {
                                            if (versionInfo.Contains(kw.ToLowerInvariant()))
                                            {
                                                Punisher.LogWarn($"Suspicious file version: {vi.ProductName} ({path})");
                                                Punisher.Kill($"ver:{vi.ProductName}");
                                                return;
                                            }
                                        }
                                    }
                                }
                                catch { }
                            }
                        }
                        catch { }
                    } while (Native.Process32NextW(snap, ref pe));
                }
                finally
                {
                    Native.CloseHandle(snap);
                }
            }
            catch (Exception ex) { Punisher.LogWarn("ExternalGuard.ScanProcesses ex: " + ex.Message); }
        }

        public static void ScanWindows()
        {
            try
            {
                Native.EnumWindows((hWnd, lParam) =>
                {
                    try
                    {
                        if (!Native.IsWindowVisible(hWnd))
                            return true;

                        var sb = new StringBuilder(512);
                        if (Native.GetWindowTextW(hWnd, sb, sb.Capacity) > 0)
                        {
                            string title = sb.ToString();
                            string lower = title.ToLowerInvariant();

                            foreach (var kw in Blacklist.SuspiciousWindowKeywords)
                            {
                                if (lower.Contains(kw))
                                {
                                    Native.GetWindowThreadProcessId(hWnd, out uint pid);
                                    Punisher.LogWarn($"Suspicious window: '{title}' pid={pid}");
                                    Punisher.Kill($"wnd:{title}");
                                    return false;
                                }
                            }
                        }

                        var cb = new StringBuilder(256);
                        if (Native.GetClassNameW(hWnd, cb, cb.Capacity) > 0)
                        {
                            string cls = cb.ToString();
                            string clsLower = cls.ToLowerInvariant();

                            if (clsLower.Contains("cheatengine") || clsLower.Contains("tcheatengine"))
                            {
                                Native.GetWindowThreadProcessId(hWnd, out uint pid);
                                Punisher.LogWarn($"Suspicious window class: '{cls}' pid={pid}");
                                Punisher.Kill($"wndcls:{cls}");
                                return false;
                            }
                        }
                    }
                    catch { }
                    return true;
                }, IntPtr.Zero);
            }
            catch (Exception ex) { Punisher.LogWarn("ExternalGuard.ScanWindows ex: " + ex.Message); }
        }

        public static void ScanCheatEngine()
        {
            try
            {
                Native.EnumWindows((hWnd, lParam) =>
                {
                    try
                    {
                        if (!Native.IsWindowVisible(hWnd))
                            return true;

                        var sb = new StringBuilder(512);
                        if (Native.GetWindowTextW(hWnd, sb, sb.Capacity) > 0)
                        {
                            string title = sb.ToString();
                            string lower = title.ToLowerInvariant();

                            foreach (var kw in Blacklist.CheatEngineWindowKeywords)
                            {
                                if (lower.Contains(kw))
                                {
                                    Native.GetWindowThreadProcessId(hWnd, out uint pid);
                                    Punisher.LogWarn($"CE window: '{title}' pid={pid}");
                                    Punisher.Kill($"ce:{title}");
                                    return false;
                                }
                            }
                        }
                    }
                    catch { }
                    return true;
                }, IntPtr.Zero);

                uint currentPid = Native.GetCurrentProcessId();
                var snap = Native.CreateToolhelp32Snapshot(Native.TH32CS_SNAPPROCESS, 0);
                if (snap == IntPtr.Zero || snap == (IntPtr)(-1))
                    return;

                try
                {
                    var pe = new Native.PROCESSENTRY32();
                    pe.dwSize = (uint)Marshal.SizeOf<Native.PROCESSENTRY32>();
                    if (!Native.Process32FirstW(snap, ref pe))
                        return;

                    do
                    {
                        if (pe.th32ProcessID == currentPid)
                            continue;
                        string name = (pe.szExeFile ?? "").ToLowerInvariant();
                        if (name.Contains("cheatengine") || name.Contains("cheat engine") || name.Contains("ce-x86_64") || name.Contains("ce-x86"))
                        {
                            Punisher.LogWarn($"CE process: {name} pid={pe.th32ProcessID}");
                            Punisher.Kill($"ceproc:{name}");
                            return;
                        }
                    } while (Native.Process32NextW(snap, ref pe));
                }
                finally
                {
                    Native.CloseHandle(snap);
                }
            }
            catch (Exception ex) { Punisher.LogWarn("ExternalGuard.ScanCheatEngine ex: " + ex.Message); }
        }

        public static void ScanHttpDebugger()
        {
            try
            {
                uint currentPid = Native.GetCurrentProcessId();
                var snap = Native.CreateToolhelp32Snapshot(Native.TH32CS_SNAPPROCESS, 0);
                if (snap == IntPtr.Zero || snap == (IntPtr)(-1))
                    return;

                try
                {
                    var pe = new Native.PROCESSENTRY32();
                    pe.dwSize = (uint)Marshal.SizeOf<Native.PROCESSENTRY32>();
                    if (!Native.Process32FirstW(snap, ref pe))
                        return;

                    do
                    {
                        if (pe.th32ProcessID == currentPid)
                            continue;
                        string name = (pe.szExeFile ?? "").ToLowerInvariant();
                        foreach (var hd in Blacklist.HttpDebuggerProcessNames)
                        {
                            if (name.Contains(hd))
                            {
                                Punisher.LogWarn($"HTTP Debugger process: {name} pid={pe.th32ProcessID}");
                                Punisher.Kill($"hdproc:{name}");
                                return;
                            }
                        }
                    } while (Native.Process32NextW(snap, ref pe));
                }
                finally
                {
                    Native.CloseHandle(snap);
                }

                Native.EnumWindows((hWnd, lParam) =>
                {
                    try
                    {
                        if (!Native.IsWindowVisible(hWnd))
                            return true;

                        var sb = new StringBuilder(512);
                        if (Native.GetWindowTextW(hWnd, sb, sb.Capacity) > 0)
                        {
                            string title = sb.ToString();
                            string lower = title.ToLowerInvariant();
                            foreach (var kw in Blacklist.HttpDebuggerKeywords)
                            {
                                if (lower.Contains(kw))
                                {
                                    Native.GetWindowThreadProcessId(hWnd, out uint pid);
                                    Punisher.LogWarn($"HTTP Debugger window: '{title}' pid={pid}");
                                    Punisher.Kill($"hdwnd:{title}");
                                    return false;
                                }
                            }
                        }
                    }
                    catch { }
                    return true;
                }, IntPtr.Zero);
            }
            catch (Exception ex) { Punisher.LogWarn("ExternalGuard.ScanHttpDebugger ex: " + ex.Message); }
        }
    }
}
