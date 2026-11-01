using System.IO.Ports;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace AegisKeyTray;

public class HardwareBridgeClient
{
    private readonly HttpClient _http;
    private readonly string _baseUrl;

    public HardwareBridgeClient(string baseUrl = "http://127.0.0.1:5678", double timeoutSeconds = 3.0)
    {
        _baseUrl = baseUrl.TrimEnd('/');
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(timeoutSeconds) };
        _http.DefaultRequestHeaders.Add("User-Agent", "AegisKeyTray-DotNet/1.0");
    }

    public async Task<DeviceInfo> DetectDeviceAsync()
    {
        // 1. Fast bridge check
        try
        {
            var res = await _http.GetFromJsonAsync<JsonObject>($"{_baseUrl}/bridge/status");
            if (res != null && res["connected"] != null)
            {
                bool isConnected = res["connected"]?.GetValue<bool>() ?? false;
                string portName = res["port"]?.GetValue<string>() ?? DetectSerialPort();
                return new DeviceInfo(
                    Product: "AegisKey S3 Authenticator",
                    Chip: "ESP32-S3 (Dual Core Xtensa LX7 @ 240MHz)",
                    Vid: "0x303A",
                    Pid: "0xAE61",
                    Port: portName,
                    Connected: isConnected,
                    StatusText: isConnected ? "Connected" : "Disconnected"
                );
            }
        }
        catch { }

        // 2. Fallback to /api/status
        try
        {
            var res = await _http.GetFromJsonAsync<JsonObject>($"{_baseUrl}/api/status");
            if (res != null && res["ok"]?.GetValue<bool>() == true)
            {
                bool isOnline = res["status"]?.GetValue<string>() == "online";
                string port = res["port"]?.GetValue<string>() ?? DetectSerialPort();
                return new DeviceInfo(
                    Product: res["product"]?.GetValue<string>() ?? "AegisKey S3 Authenticator",
                    Chip: res["chip"]?.GetValue<string>() ?? "ESP32-S3",
                    Vid: res["vid"]?.GetValue<string>() ?? "0x303A",
                    Pid: res["pid"]?.GetValue<string>() ?? "0xAE61",
                    Port: port,
                    Connected: isOnline,
                    StatusText: isOnline ? "Connected" : "Device Offline"
                );
            }
        }
        catch { }

        string localPort = DetectSerialPort();
        return new DeviceInfo(
            Product: "AegisKey S3 Authenticator",
            Chip: "ESP32-S3",
            Vid: "0x303A",
            Pid: "0xAE61",
            Port: localPort,
            Connected: false,
            StatusText: "Disconnected"
        );
    }

    private static string DetectSerialPort()
    {
        try
        {
            var ports = SerialPort.GetPortNames();
            if (ports.Contains("COM7")) return "COM7";
            if (ports.Length > 0) return ports[0];
        }
        catch { }
        return "COM7";
    }

    public async Task<SecureGuardStatus> GetSecureGuardStatusAsync()
    {
        try
        {
            var res = await _http.GetFromJsonAsync<JsonObject>($"{_baseUrl}/api/secure-guard/status");
            if (res != null && res["ok"]?.GetValue<bool>() == true)
            {
                return new SecureGuardStatus(
                    State: res["state"]?.GetValue<int>() ?? 0,
                    StateName: res["state_name"]?.GetValue<string>() ?? "Unprovisioned",
                    Provisioned: res["provisioned"]?.GetValue<bool>() ?? false,
                    Unlocked: res["unlocked"]?.GetValue<bool>() ?? false,
                    FailedAttempts: res["failed_attempts"]?.GetValue<int>() ?? 0,
                    RemainingAttempts: res["remaining_attempts"]?.GetValue<int>() ?? 5,
                    MaxAttempts: res["max_attempts"]?.GetValue<int>() ?? 5,
                    SessionRemainingMs: res["session_remaining_ms"]?.GetValue<int>() ?? 0,
                    RateLimitRemainingMs: res["rate_limit_remaining_ms"]?.GetValue<int>() ?? 0
                );
            }
        }
        catch { }
        return new SecureGuardStatus();
    }

    public async Task<bool> UnlockSecureGuardAsync(string pin)
    {
        try
        {
            var res = await _http.PostAsJsonAsync($"{_baseUrl}/api/secure-guard/unlock", new { pin });
            var json = await res.Content.ReadFromJsonAsync<JsonObject>();
            return json != null && json["ok"]?.GetValue<bool>() == true;
        }
        catch
        {
            return false;
        }
    }

    public async Task<bool> LockSecureGuardAsync()
    {
        try
        {
            var res = await _http.PostAsJsonAsync($"{_baseUrl}/api/secure-guard/lock", new { });
            var json = await res.Content.ReadFromJsonAsync<JsonObject>();
            return json != null && json["ok"]?.GetValue<bool>() == true;
        }
        catch
        {
            return false;
        }
    }

    public async Task<bool> WipeSelectiveAsync(string pin)
    {
        try
        {
            var res = await _http.PostAsJsonAsync($"{_baseUrl}/api/secure-guard/wipe-selective", new
            {
                scope = 0,
                confirmation = "CONFIRM_WIPE_AEGIS_GUARD",
                pin
            });
            var json = await res.Content.ReadFromJsonAsync<JsonObject>();
            return json != null && json["ok"]?.GetValue<bool>() == true;
        }
        catch
        {
            return false;
        }
    }

    public async Task<bool> ResetDeviceAsync(string pin)
    {
        try
        {
            var res = await _http.PostAsJsonAsync($"{_baseUrl}/api/reset", new { pin });
            var json = await res.Content.ReadFromJsonAsync<JsonObject>();
            return json != null && json["ok"]?.GetValue<bool>() == true;
        }
        catch
        {
            return false;
        }
    }

    public async Task<List<VaultItem>> GetVaultKeysAsync()
    {
        var list = new List<VaultItem>();
        try
        {
            var res = await _http.GetFromJsonAsync<JsonObject>($"{_baseUrl}/api/vault");
            if (res != null && res["items"] is JsonArray arr)
            {
                foreach (var item in arr)
                {
                    if (item == null) continue;
                    list.Add(new VaultItem(
                        SlotId: item["slotId"]?.GetValue<int>() ?? 0,
                        Label: item["label"]?.GetValue<string>() ?? "",
                        Type: item["type"]?.GetValue<string>() ?? "PASSKEY_FIDO",
                        PublicSummary: item["publicSummary"]?.GetValue<string>() ?? "",
                        AlgorithmOrCurve: item["algorithmOrCurve"]?.GetValue<string>() ?? "Ed25519",
                        UsageDescription: item["usageDescription"]?.GetValue<string>() ?? ""
                    ));
                }
            }
        }
        catch { }
        return list;
    }

    public async Task<List<WalletItem>> GetWalletsAsync()
    {
        var list = new List<WalletItem>();
        try
        {
            var res = await _http.GetFromJsonAsync<JsonObject>($"{_baseUrl}/api/wallet/list");
            if (res != null && res["wallets"] is JsonArray arr)
            {
                foreach (var w in arr)
                {
                    if (w == null) continue;
                    list.Add(new WalletItem(
                        Slot: w["slot"]?.GetValue<int>() ?? 0,
                        Label: w["label"]?.GetValue<string>() ?? "",
                        Address: w["address"]?.GetValue<string>() ?? ""
                    ));
                }
            }
        }
        catch { }
        return list;
    }

    public async Task<List<OathAccount>> GetOathAccountsAsync()
    {
        var list = new List<OathAccount>();
        try
        {
            var res = await _http.GetFromJsonAsync<JsonObject>($"{_baseUrl}/api/oath/list");
            if (res != null && res["accounts"] is JsonArray arr)
            {
                foreach (var a in arr)
                {
                    if (a == null) continue;
                    list.Add(new OathAccount(
                        Name: a["name"]?.GetValue<string>() ?? "Account",
                        Code: a["code"]?.GetValue<string>() ?? "000000",
                        Period: a["period"]?.GetValue<int>() ?? 30
                    ));
                }
            }
        }
        catch { }
        return list;
    }

    public async Task<ProximityStatus> GetProximityStatusAsync()
    {
        try
        {
            var res = await _http.GetFromJsonAsync<JsonObject>($"{_baseUrl}/api/proximity/status");
            if (res != null)
            {
                return new ProximityStatus(
                    Enabled: res["enabled"]?.GetValue<bool>() ?? true,
                    State: res["state"]?.GetValue<string>() ?? "Armed",
                    RssiDbm: res["rssi_dbm"]?.GetValue<int>() ?? -35,
                    ThresholdDbm: res["threshold_dbm"]?.GetValue<int>() ?? -75
                );
            }
        }
        catch { }
        return new ProximityStatus();
    }

    public async Task<bool> CreateKeyAsync(string type, string label, int curve = -8)
    {
        try
        {
            var res = await _http.PostAsJsonAsync($"{_baseUrl}/api/key/create", new
            {
                type,
                label,
                curve = curve.ToString()
            });
            var json = await res.Content.ReadFromJsonAsync<JsonObject>();
            return json != null && json["ok"]?.GetValue<bool>() == true;
        }
        catch
        {
            return false;
        }
    }

    public async Task<bool> DeleteKeyAsync(int slotId)
    {
        try
        {
            var res = await _http.PostAsJsonAsync($"{_baseUrl}/api/key/delete", new { slot = slotId });
            var json = await res.Content.ReadFromJsonAsync<JsonObject>();
            return json != null && json["ok"]?.GetValue<bool>() == true;
        }
        catch
        {
            return false;
        }
    }

    public async Task<List<ShamirShare>> ShamirSplitAsync(string? secretHex = null)
    {
        var shares = new List<ShamirShare>();
        try
        {
            var payload = secretHex != null ? new { secret_hex = secretHex } : new object();
            var res = await _http.PostAsJsonAsync($"{_baseUrl}/api/backup/shamir-split", payload);
            var json = await res.Content.ReadFromJsonAsync<JsonObject>();
            if (json != null && json["shares"] is JsonArray arr)
            {
                foreach (var sh in arr)
                {
                    if (sh == null) continue;
                    shares.Add(new ShamirShare(
                        Index: sh["index"]?.GetValue<int>() ?? 0,
                        Description: sh["description"]?.GetValue<string>() ?? "",
                        ShareHex: sh["share_hex"]?.GetValue<string>() ?? ""
                    ));
                }
            }
        }
        catch { }
        return shares;
    }

    public async Task<string?> ClearSignPreviewAsync(string txType, string to, string amount, string fee)
    {
        try
        {
            var payload = new { tx_type = txType, to, amount, fee };
            var res = await _http.PostAsJsonAsync($"{_baseUrl}/api/wallet/clear-sign-preview", payload);
            var json = await res.Content.ReadFromJsonAsync<JsonObject>();
            if (json != null && json["screen"]?["ascii_frame"] is JsonArray arr)
            {
                return string.Join(Environment.NewLine, arr.Select(x => x?.ToString() ?? ""));
            }
        }
        catch { }
        return null;
    }
}
