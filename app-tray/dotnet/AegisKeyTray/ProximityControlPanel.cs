using System.Drawing;
using System.Windows.Forms;

namespace AegisKeyTray;

/// <summary>
/// Organismo UI desacoplado (Atomic Model / Component Driven) responsável pelo
/// painel de proximidade Bluetooth e Windows Dynamic Lock.
/// </summary>
public class ProximityControlPanel : Panel
{
    private static readonly Color ColorCard = ColorTranslator.FromHtml("#111827");
    private static readonly Color ColorInputBg = ColorTranslator.FromHtml("#1A2234");
    private static readonly Color ColorCyan = ColorTranslator.FromHtml("#00E5FF");
    private static readonly Color ColorEmerald = ColorTranslator.FromHtml("#10B981");
    private static readonly Color ColorAmber = ColorTranslator.FromHtml("#F59E0B");
    private static readonly Color ColorCoral = ColorTranslator.FromHtml("#EF4444");
    private static readonly Color ColorTextPrimary = ColorTranslator.FromHtml("#F9FAFB");
    private static readonly Color ColorTextMuted = ColorTranslator.FromHtml("#9CA3AF");

    private readonly HardwareBridgeClient _client;
    private readonly Func<Task> _onStateChanged;
    private readonly Label _lblProxArmed;
    private readonly Label _lblRegisteredDevice;
    private readonly Label _lblProxSignal;
    private readonly CheckBox _chkLockWindows;
    private readonly Button _btnRegisterBt;
    private readonly Button _btnSimNear;
    private readonly Button _btnSimAway;

    [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
    public bool EnforceWindowsLock
    {
        get => _chkLockWindows.Checked;
        set => _chkLockWindows.Checked = value;
    }

    public ProximityControlPanel(HardwareBridgeClient client, Func<Task> onStateChanged)
    {
        _client = client;
        _onStateChanged = onStateChanged;

        Size = new Size(306, 175);
        BackColor = ColorInputBg;
        Padding = new Padding(8);

        _lblProxArmed = new Label
        {
            Text = "Status: ⏳ AGUARDANDO REGISTRO BLE",
            Font = new Font("Segoe UI", 8F, FontStyle.Bold),
            ForeColor = ColorAmber,
            AutoSize = true,
            Location = new Point(8, 8)
        };

        _lblRegisteredDevice = new Label
        {
            Text = "Dispositivo: Nenhum pareado em memória",
            Font = new Font("Segoe UI", 7.5F, FontStyle.Bold),
            ForeColor = ColorCyan,
            AutoSize = true,
            Location = new Point(8, 28)
        };

        _lblProxSignal = new Label
        {
            Text = "RSSI: -35 dBm  |  Limite: -75 dBm\nModo Dynamic Lock: Ativo",
            Font = new Font("Segoe UI", 7F),
            ForeColor = ColorTextMuted,
            Size = new Size(290, 26),
            Location = new Point(8, 48)
        };

        _chkLockWindows = new CheckBox
        {
            Text = "🖥️ Bloquear PC (Windows Hello) ao Afastar",
            Checked = true,
            ForeColor = ColorTextPrimary,
            Font = new Font("Segoe UI", 7.5F),
            AutoSize = true,
            Location = new Point(8, 76),
            Cursor = Cursors.Hand
        };
        _chkLockWindows.CheckedChanged += async (s, e) =>
        {
            await _onStateChanged();
        };

        _btnRegisterBt = new Button
        {
            Text = "📲 Registrar Bluetooth do Windows em Memória",
            Font = new Font("Segoe UI", 7.5F, FontStyle.Bold),
            BackColor = ColorCard,
            ForeColor = ColorCyan,
            FlatStyle = FlatStyle.Flat,
            Size = new Size(290, 26),
            Location = new Point(8, 102),
            Cursor = Cursors.Hand
        };
        _btnRegisterBt.FlatAppearance.BorderColor = ColorCyan;
        _btnRegisterBt.FlatAppearance.BorderSize = 1;
        _btnRegisterBt.Click += async (s, e) =>
        {
            var topForm = FindForm();
            if (topForm != null)
            {
                bool registered = await BluetoothRegistrationDialog.PromptAndRegisterAsync(topForm, _client, _chkLockWindows.Checked);
                if (registered)
                {
                    await _onStateChanged();
                }
            }
        };

        _btnSimNear = new Button
        {
            Text = "🟢 Perto (-35 dBm)",
            Font = new Font("Segoe UI", 7.5F, FontStyle.Bold),
            BackColor = ColorCard,
            ForeColor = ColorEmerald,
            FlatStyle = FlatStyle.Flat,
            Size = new Size(140, 26),
            Location = new Point(8, 134),
            Cursor = Cursors.Hand
        };
        _btnSimNear.FlatAppearance.BorderColor = ColorEmerald;
        _btnSimNear.FlatAppearance.BorderSize = 1;
        _btnSimNear.Click += async (s, e) =>
        {
            await _client.UpdateProximityRssiAsync(-35, 1.0, "tray_app");
            await _onStateChanged();
        };

        _btnSimAway = new Button
        {
            Text = "🔴 Longe (-92 dBm)",
            Font = new Font("Segoe UI", 7.5F, FontStyle.Bold),
            BackColor = ColorCard,
            ForeColor = ColorCoral,
            FlatStyle = FlatStyle.Flat,
            Size = new Size(140, 26),
            Location = new Point(158, 134),
            Cursor = Cursors.Hand
        };
        _btnSimAway.FlatAppearance.BorderColor = ColorCoral;
        _btnSimAway.FlatAppearance.BorderSize = 1;
        _btnSimAway.Click += async (s, e) =>
        {
            await _client.UpdateProximityRssiAsync(-92, 10.0, "tray_app");
            await _onStateChanged();
        };

        Controls.AddRange(new Control[] {
            _lblProxArmed, _lblRegisteredDevice, _lblProxSignal,
            _chkLockWindows, _btnRegisterBt, _btnSimNear, _btnSimAway
        });
    }

    public void UpdateStatus(ProximityStatus status)
    {
        bool isRegistered = !string.IsNullOrEmpty(status.BleMac) && status.BleMac != "00:00:00:00:00:00";
        bool isAway = status.State.Equals("Away", StringComparison.OrdinalIgnoreCase) ||
                      (status.RssiDbm < status.ThresholdDbm && status.RssiDbm != 0);

        if (!isRegistered)
        {
            _lblProxArmed.Text = "Status: ⏳ AGUARDANDO REGISTRO BLE";
            _lblProxArmed.ForeColor = ColorAmber;
            _lblRegisteredDevice.Text = "Dispositivo: Nenhum pareado em memória";
        }
        else if (isAway)
        {
            _lblProxArmed.Text = "Status: 🚨 AFASTADO (Cofres e Chaves Bloqueados)";
            _lblProxArmed.ForeColor = ColorCoral;
            _lblRegisteredDevice.Text = $"Dispositivo: {status.BleName} ({status.BleMac})";
        }
        else
        {
            _lblProxArmed.Text = "Status: 🛡️ ARMADO (Vigília Proximidade Ativa)";
            _lblProxArmed.ForeColor = ColorEmerald;
            _lblRegisteredDevice.Text = $"Dispositivo: {status.BleName} ({status.BleMac})";
        }

        _lblProxSignal.Text = $"RSSI: {status.RssiDbm} dBm  |  Limite: {status.ThresholdDbm} dBm\nModo Dynamic Lock: {(_chkLockWindows.Checked ? "PC Lock Ativo" : "Apenas Cofre")}";
    }
}
