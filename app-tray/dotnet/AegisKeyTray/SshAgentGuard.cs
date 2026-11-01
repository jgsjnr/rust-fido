using System.Diagnostics;
using System.IO;

namespace AegisKeyTray;

public class SshAgentGuard
{
    private readonly HardwareBridgeClient _client;
    private readonly Action<string, string, int>? _onNotification; // title, message, iconType (1 info, 2 warn)
    private System.Threading.Timer? _timer;
    private int _lastState = -1;
    private bool? _lastConnected = null;
    private static readonly string AuthGrantFile = Path.Combine(Path.GetTempPath(), "aegis_ssh_session_grant.json");

    public SshAgentGuard(HardwareBridgeClient client, Action<string, string, int>? onNotification = null)
    {
        _client = client;
        _onNotification = onNotification;
    }

    public void StartWatchdog(int intervalSeconds = 2)
    {
        _timer = new System.Threading.Timer(async _ =>
        {
            try
            {
                await TickAsync();
            }
            catch { }
        }, null, 0, intervalSeconds * 1000);
    }

    public void StopWatchdog()
    {
        _timer?.Dispose();
        _timer = null;
    }

    private async Task TickAsync()
    {
        try
        {
            var dev = await _client.DetectDeviceAsync();
            var sg = await _client.GetSecureGuardStatusAsync();

            bool isConnected = dev.Connected;
            int currentState = sg.State;

            if (_lastConnected != null)
            {
                // 1. TRANSITION: Disconnected -> Connected
                if (_lastConnected == false && isConnected)
                {
                    string title = I18n.T("notif_conn_title");
                    string msg = I18n.T("notif_conn_body", dev.Port, sg.StateName);
                    _onNotification?.Invoke(title, msg, 1);
                }
                // 2. TRANSITION: Connected -> Disconnected
                else if (_lastConnected == true && !isConnected)
                {
                    string title = I18n.T("notif_disconn_title");
                    string msg = I18n.T("notif_disconn_body");
                    PurgeSshAgent();
                    RevokeSessionGrant();
                    _onNotification?.Invoke(title, msg, 2);
                }

                // 3. TRANSITION: Locked -> Unlocked
                if (_lastState != 4 && currentState == 4 && isConnected)
                {
                    string title = I18n.T("notif_unlocked_title");
                    string msg = I18n.T("notif_unlocked_body");
                    _onNotification?.Invoke(title, msg, 1);
                }
                // 4. TRANSITION: Unlocked -> Locked
                else if (_lastState == 4 && currentState != 4)
                {
                    string title = I18n.T("notif_locked_title");
                    string msg = I18n.T("notif_locked_body");
                    PurgeSshAgent();
                    RevokeSessionGrant();
                    _onNotification?.Invoke(title, msg, 2);
                }
            }

            _lastState = currentState;
            _lastConnected = isConnected;
        }
        catch { }
    }

    public string PurgeSshAgent()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = FindSshAddPath(),
                Arguments = "-D",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc != null)
            {
                proc.WaitForExit(3000);
                string outStr = proc.StandardOutput.ReadToEnd().Trim();
                string errStr = proc.StandardError.ReadToEnd().Trim();
                return string.IsNullOrEmpty(outStr) ? errStr : outStr;
            }
        }
        catch (Exception ex)
        {
            return $"Error: {ex.Message}";
        }
        return "ssh-add executed";
    }

    public (int Count, string Message) GetAgentIdentitiesCount()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = FindSshAddPath(),
                Arguments = "-l",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc != null)
            {
                proc.WaitForExit(3000);
                string outStr = proc.StandardOutput.ReadToEnd().Trim();
                if (outStr.Contains("The agent has no identities") || proc.ExitCode == 1)
                    return (0, "No identities cached");
                if (proc.ExitCode == 2)
                    return (0, "Agent service stopped or unreachable");

                var lines = outStr.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                return (lines.Length, $"{lines.Length} identity/identities cached");
            }
        }
        catch (Exception ex)
        {
            return (0, ex.Message);
        }
        return (0, "Unknown");
    }

    public (bool Success, string Message) LoadResidentFido2Keys()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = FindSshAddPath(),
                Arguments = "-K",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc != null)
            {
                proc.WaitForExit(5000);
                string outStr = proc.StandardOutput.ReadToEnd().Trim();
                string errStr = proc.StandardError.ReadToEnd().Trim();
                bool ok = proc.ExitCode == 0;
                return (ok, ok ? (outStr.Length > 0 ? outStr : "Resident keys loaded") : errStr);
            }
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
        return (false, "Could not run ssh-add");
    }

    public static void RevokeSessionGrant()
    {
        try
        {
            if (File.Exists(AuthGrantFile))
                File.Delete(AuthGrantFile);
        }
        catch { }
    }

    public static string FindSshAddPath()
    {
        string defaultPath = @"C:\WINDOWS\System32\OpenSSH\ssh-add.exe";
        if (File.Exists(defaultPath)) return defaultPath;
        return "ssh-add.exe";
    }
}
