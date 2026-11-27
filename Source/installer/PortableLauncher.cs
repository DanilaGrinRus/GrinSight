// Single-file Windows distribution. Only the published application is cached.
// Wallet data is addressed relative to the outer executable, even after an update.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;

internal static class PortableLauncher
{
    private static readonly Assembly Self = Assembly.GetExecutingAssembly();

    private static void RejectLink(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("A link was found inside the application cache.");
    }

    private static string DirectoryUnder(string parent, string name)
    {
        string path = Path.Combine(parent, name);
        Directory.CreateDirectory(path);
        RejectLink(path);
        return path;
    }

    private static FileStream LockCache(string path)
    {
        Stopwatch timer = Stopwatch.StartNew();
        while (true)
        {
            try
            {
                if (File.Exists(path)) RejectLink(path);
                return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            }
            catch (IOException error)
            {
                int code = error.HResult & 65535;
                if ((code != 32 && code != 33) || timer.Elapsed.TotalSeconds >= 90) throw;
                Thread.Sleep(80);
            }
        }
    }

    private static bool Matches(string path, string digest, long size)
    {
        if (!File.Exists(path)) return false;
        RejectLink(path);
        using (var input = File.OpenRead(path))
        using (var hash = SHA256.Create())
        {
            if (input.Length != size) return false;
            string actual = BitConverter.ToString(hash.ComputeHash(input)).Replace("-", "");
            return String.Equals(actual, digest, StringComparison.OrdinalIgnoreCase);
        }
    }

    private static void Restore(ZipArchiveEntry entry, string target, string digest, long size)
    {
        if (entry == null || entry.Length != size) throw new InvalidDataException("Incomplete package.");
        string partial = target + ".partial";
        if (File.Exists(partial))
        {
            RejectLink(partial);
            File.Delete(partial);
        }
        using (var input = entry.Open())
        using (var output = new FileStream(partial, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            input.CopyTo(output);
        if (!Matches(partial, digest, size)) throw new InvalidDataException("Application file verification failed.");
        // An interrupted repair can leave a missing target. The next run repeats this step.
        if (File.Exists(target)) File.Delete(target);
        File.Move(partial, target);
    }

    private static string Prepare(out bool bundledOnion)
    {
        bundledOnion = false;
        string local = Environment.GetEnvironmentVariable("LOCALAPPDATA");
        if (String.IsNullOrEmpty(local)) local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (String.IsNullOrEmpty(local) || !Path.IsPathRooted(local))
            throw new IOException("A local application data directory is required.");
        string cache = DirectoryUnder(DirectoryUnder(local, "GrinSightLight"), "portable-runtime");
        using (var manifest = new StreamReader(Self.GetManifestResourceStream("runtime.catalog"), Encoding.UTF8))
        {
            string runtime = DirectoryUnder(cache, manifest.ReadLine());
            using (LockCache(Path.Combine(runtime, "prepare.lock")))
            using (var payload = Self.GetManifestResourceStream("runtime.zip"))
            using (var zip = new ZipArchive(payload, ZipArchiveMode.Read))
            {
                DirectoryUnder(runtime, "bin");
                string line;
                while ((line = manifest.ReadLine()) != null)
                {
                    string[] fields = line.Split('\t');
                    if (fields[0] == @"bin\fly-onion.exe") bundledOnion = true;
                    // The build generates paths only from its fixed package allowlist.
                    string target = Path.Combine(runtime, fields[0]);
                    long length = Int64.Parse(fields[2], System.Globalization.CultureInfo.InvariantCulture);
                    if (!Matches(target, fields[1], length))
                        Restore(zip.GetEntry(fields[3]), target, fields[1], length);
                }
            }
            return runtime;
        }
    }

    // Windows argv escaping, including trailing backslashes inside quotes.
    private static string Quote(string value)
    {
        var quoted = new StringBuilder("\"");
        int slashes = 0;
        foreach (char ch in value)
        {
            if (ch == '\\') { slashes++; continue; }
            quoted.Append('\\', ch == '"' ? 2 * slashes + 1 : slashes);
            quoted.Append(ch);
            slashes = 0;
        }
        return quoted.Append('\\', 2 * slashes).Append('"').ToString();
    }

    private static string[] WindowArgs(string[] args, string runtime, bool bundledOnion)
    {
        var result = new List<string>(args);
        if (result.Contains("--snapshot") || result.Contains("--host")) return args;
        string bin = Path.Combine(runtime, "bin");
        result.AddRange(new[] { "--host", Path.Combine(bin, "fly-paycore-host.exe") });
        if (!result.Contains("--profile"))
            result.AddRange(new[] { "--profile", Path.Combine(Path.GetDirectoryName(Self.Location), "data", "profile") });
        if (!result.Contains("--scenario"))
        {
            if (!result.Contains("--chain"))
                result.AddRange(new[] { "--chain", Path.Combine(bin, "fly-chain.exe") });
            if (bundledOnion && !result.Contains("--onion"))
                result.AddRange(new[] { "--onion", Path.Combine(bin, "fly-onion.exe") });
            if (!result.Contains("--transport"))
                result.AddRange(new[] { "--transport", Path.Combine(bin, "fly-mailbox.exe") });
            if (!result.Contains("--relay"))
                result.AddRange(new[] { "--relay", "wss://relay.floonet.dev" });
        }
        return result.ToArray();
    }

    [STAThread]
    private static int Main(string[] args)
    {
        try
        {
            bool bundledOnion;
            string runtime = Prepare(out bundledOnion);
            if (args.Length == 1 && args[0] == "--prepare-only") return 0;
            if (args.Length > 0 && args[0] == "--verify-checkpoint")
            {
                if (args.Length != 3) { Console.Error.WriteLine("Usage: --verify-checkpoint main|test FILE_OR_DIRECTORY"); return 2; }
                var verify = new ProcessStartInfo(Path.Combine(runtime, @"bin\fly-chain.exe"),
                    "verify-checkpoint " + Quote(args[1]) + " " + Quote(Path.GetFullPath(args[2])));
                verify.UseShellExecute = false;
                verify.CreateNoWindow = true;
                verify.RedirectStandardOutput = true;
                verify.RedirectStandardError = true;
                using (var process = Process.Start(verify))
                {
                    Console.Out.Write(process.StandardOutput.ReadToEnd());
                    Console.Error.Write(process.StandardError.ReadToEnd());
                    process.WaitForExit();
                    return process.ExitCode;
                }
            }
            var start = new ProcessStartInfo(Path.Combine(runtime, "GrinSight.exe"),
                String.Join(" ", Array.ConvertAll(WindowArgs(args, runtime, bundledOnion), Quote)));
            start.UseShellExecute = false;
            start.WorkingDirectory = args.Length == 0 ? runtime : Environment.CurrentDirectory;
            using (var window = Process.Start(start))
            {
                window.WaitForExit();
                return window.ExitCode;
            }
        }
        catch (Exception error)
        {
            string message = "GrinSight could not prepare or start the portable application. " + error.Message;
            if (args.Length == 0) MessageBox.Show(message, "GrinSight", MessageBoxButtons.OK, MessageBoxIcon.Error);
            else Console.Error.WriteLine(message);
            return 1;
        }
    }
}
