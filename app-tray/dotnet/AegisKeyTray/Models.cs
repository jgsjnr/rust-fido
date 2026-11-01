using System.Text.Json.Serialization;

namespace AegisKeyTray;

public record DeviceInfo(
    string Product = "AegisKey S3 Authenticator",
    string Chip = "ESP32-S3 (Xtensa LX7 @ 240MHz)",
    string Vid = "0x303A",
    string Pid = "0xAE61",
    string Port = "COM7",
    bool Connected = false,
    string StatusText = "Disconnected"
);

public record SecureGuardStatus(
    [property: JsonPropertyName("state")] int State = 0,
    [property: JsonPropertyName("state_name")] string StateName = "Unprovisioned",
    [property: JsonPropertyName("provisioned")] bool Provisioned = false,
    [property: JsonPropertyName("unlocked")] bool Unlocked = false,
    [property: JsonPropertyName("failed_attempts")] int FailedAttempts = 0,
    [property: JsonPropertyName("remaining_attempts")] int RemainingAttempts = 5,
    [property: JsonPropertyName("max_attempts")] int MaxAttempts = 5,
    [property: JsonPropertyName("session_remaining_ms")] int SessionRemainingMs = 0,
    [property: JsonPropertyName("rate_limit_remaining_ms")] int RateLimitRemainingMs = 0,
    [property: JsonPropertyName("inactivity_timeout_ms")] int InactivityTimeoutMs = 120000
);

public record VaultItem(
    [property: JsonPropertyName("slotId")] int SlotId,
    [property: JsonPropertyName("label")] string Label,
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("publicSummary")] string PublicSummary,
    [property: JsonPropertyName("algorithmOrCurve")] string AlgorithmOrCurve,
    [property: JsonPropertyName("usageDescription")] string UsageDescription
);

public record WalletItem(
    [property: JsonPropertyName("slot")] int Slot,
    [property: JsonPropertyName("label")] string Label,
    [property: JsonPropertyName("address")] string Address
);

public record OathAccount(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("code")] string Code,
    [property: JsonPropertyName("period")] int Period = 30
);

public record ProximityStatus(
    [property: JsonPropertyName("enabled")] bool Enabled = true,
    [property: JsonPropertyName("state")] string State = "Armed",
    [property: JsonPropertyName("rssi_dbm")] int RssiDbm = -35,
    [property: JsonPropertyName("threshold_dbm")] int ThresholdDbm = -75
);

public record ShamirShare(
    [property: JsonPropertyName("index")] int Index,
    [property: JsonPropertyName("description")] string Description,
    [property: JsonPropertyName("share_hex")] string ShareHex
);

public record EfuseGuardStatus(
    [property: JsonPropertyName("ok")] bool Ok = true,
    [property: JsonPropertyName("burn_allowed")] bool BurnAllowed = false,
    [property: JsonPropertyName("warning")] string Warning = "",
    [property: JsonPropertyName("safe_development_override")] bool SafeDevelopmentOverride = true
);

public record SystemAuthRequest(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("source")] string Source,
    [property: JsonPropertyName("operation")] string Operation,
    [property: JsonPropertyName("reason")] string Reason,
    [property: JsonPropertyName("timestamp")] double Timestamp,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("approved")] bool Approved
);
