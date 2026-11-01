using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace AegisKeyTray;

public class PinSessionDialog : Form
{
    private static readonly Color ColorBg = ColorTranslator.FromHtml("#0B0F19");
    private static readonly Color ColorCard = ColorTranslator.FromHtml("#111827");
    private static readonly Color ColorCyan = ColorTranslator.FromHtml("#00E5FF");
    private static readonly Color ColorEmerald = ColorTranslator.FromHtml("#10B981");
    private static readonly Color ColorAmber = ColorTranslator.FromHtml("#F59E0B");
    private static readonly Color ColorCoral = ColorTranslator.FromHtml("#EF4444");
    private static readonly Color ColorTextPrimary = ColorTranslator.FromHtml("#F9FAFB");
    private static readonly Color ColorTextMuted = ColorTranslator.FromHtml("#9CA3AF");
    private static readonly Color ColorInputBg = ColorTranslator.FromHtml("#1A2234");

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    private readonly HardwareBridgeClient _client;
    private readonly bool _performHardwareUnlock;
    private readonly string _reason;
    private readonly string _subtitle;

    private TextBox _txtPin = null!;
    private Label _lblStatusMsg = null!;
    private Label _lblAttempts = null!;
    private Button _btnSubmit = null!;
    private bool _isBusy;

    public string EnteredPin { get; private set; } = "";

    public PinSessionDialog(
        HardwareBridgeClient client,
        string reason = "System Request: Hardware Access",
        string subtitle = "Digite o PIN do Secure Guard para autorizar a chave física.",
        bool performHardwareUnlock = true)
    {
        _client = client;
        _reason = reason;
        _subtitle = subtitle;
        _performHardwareUnlock = performHardwareUnlock;

        InitializeComponent();
    }

    private void InitializeComponent()
    {
        Text = "AegisKey — Autorização de Hardware";
        Size = new Size(340, 500);
        MinimumSize = new Size(340, 500);
        MaximumSize = new Size(340, 500);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = true;
        TopMost = true;
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = ColorBg;
        ForeColor = ColorTextPrimary;
        Font = new Font("Segoe UI", 9F, FontStyle.Regular);

        // Header Panel
        var pnlHeader = new Panel
        {
            Dock = DockStyle.Top,
            Height = 120,
            BackColor = ColorCard,
            Padding = new Padding(16, 12, 16, 8)
        };

        var lblBrand = new Label
        {
            Text = "🛡️ AEGISKEY SECURE GUARD",
            Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
            ForeColor = ColorCyan,
            AutoSize = true,
            Location = new Point(14, 10)
        };

        var lblReason = new Label
        {
            Text = _reason,
            Font = new Font("Segoe UI", 10.5F, FontStyle.Bold),
            ForeColor = ColorTextPrimary,
            Size = new Size(295, 38),
            Location = new Point(14, 30)
        };

        var lblSub = new Label
        {
            Text = _subtitle,
            Font = new Font("Segoe UI", 7.5F),
            ForeColor = ColorTextMuted,
            Size = new Size(295, 26),
            Location = new Point(14, 70)
        };

        _lblAttempts = new Label
        {
            Text = "ESP32-S3 (COM7) • Tentativas: [5/5]",
            Font = new Font("Segoe UI", 7.5F, FontStyle.Bold),
            ForeColor = ColorAmber,
            AutoSize = true,
            Location = new Point(14, 98)
        };

        pnlHeader.Controls.AddRange(new Control[] { lblBrand, lblReason, lblSub, _lblAttempts });
        Controls.Add(pnlHeader);

        // Status / Error message label
        _lblStatusMsg = new Label
        {
            Text = "Insira o PIN e confirme:",
            Font = new Font("Segoe UI", 8F, FontStyle.Bold),
            ForeColor = ColorTextMuted,
            TextAlign = ContentAlignment.MiddleCenter,
            Size = new Size(300, 20),
            Location = new Point(12, 128)
        };
        Controls.Add(_lblStatusMsg);

        // PIN Input
        var pnlPinBox = new Panel
        {
            Size = new Size(290, 42),
            Location = new Point(18, 150),
            BackColor = ColorInputBg,
            Padding = new Padding(6)
        };

        _txtPin = new TextBox
        {
            Dock = DockStyle.Fill,
            PasswordChar = '●',
            Font = new Font("Segoe UI", 15F, FontStyle.Bold),
            BackColor = ColorInputBg,
            ForeColor = ColorCyan,
            BorderStyle = BorderStyle.None,
            TextAlign = HorizontalAlignment.Center,
            MaxLength = 16
        };
        _txtPin.KeyDown += (s, e) =>
        {
            if (e.KeyCode == Keys.Enter)
            {
                e.Handled = true;
                e.SuppressKeyPress = true;
                _ = SubmitPinAsync();
            }
            else if (e.KeyCode == Keys.Escape)
            {
                DialogResult = DialogResult.Cancel;
                Close();
            }
        };
        pnlPinBox.Controls.Add(_txtPin);
        Controls.Add(pnlPinBox);

        // Numeric Keypad Grid (3x4)
        var pnlKeypad = new Panel
        {
            Size = new Size(290, 210),
            Location = new Point(18, 200),
            BackColor = ColorBg
        };

        string[,] keys = {
            { "1", "2", "3" },
            { "4", "5", "6" },
            { "7", "8", "9" },
            { "⌫", "0", "➔" }
        };

        int btnW = 90;
        int btnH = 46;
        int gap = 8;

        for (int row = 0; row < 4; row++)
        {
            for (int col = 0; col < 3; col++)
            {
                string key = keys[row, col];
                var btn = new Button
                {
                    Text = key,
                    Font = new Font("Segoe UI", 12F, FontStyle.Bold),
                    Size = new Size(btnW, btnH),
                    Location = new Point(col * (btnW + gap), row * (btnH + gap)),
                    FlatStyle = FlatStyle.Flat,
                    Cursor = Cursors.Hand
                };
                btn.FlatAppearance.BorderSize = 0;

                if (key == "➔")
                {
                    btn.BackColor = ColorCyan;
                    btn.ForeColor = Color.Black;
                    _btnSubmit = btn;
                    btn.Click += (s, e) => _ = SubmitPinAsync();
                }
                else if (key == "⌫")
                {
                    btn.BackColor = ColorInputBg;
                    btn.ForeColor = ColorAmber;
                    btn.Click += (s, e) =>
                    {
                        if (_txtPin.Text.Length > 0)
                            _txtPin.Text = _txtPin.Text[..^1];
                    };
                }
                else
                {
                    btn.BackColor = ColorCard;
                    btn.ForeColor = ColorTextPrimary;
                    btn.Click += (s, e) =>
                    {
                        if (_txtPin.Text.Length < 16)
                            _txtPin.Text += key;
                    };
                }

                pnlKeypad.Controls.Add(btn);
            }
        }
        Controls.Add(pnlKeypad);

        // Bottom Cancel Button
        var btnCancel = new Button
        {
            Text = "✕ Cancelar Solicitação",
            Font = new Font("Segoe UI", 8F, FontStyle.Bold),
            BackColor = ColorBg,
            ForeColor = ColorTextMuted,
            FlatStyle = FlatStyle.Flat,
            Size = new Size(290, 28),
            Location = new Point(18, 420),
            Cursor = Cursors.Hand
        };
        btnCancel.FlatAppearance.BorderSize = 0;
        btnCancel.Click += (s, e) =>
        {
            DialogResult = DialogResult.Cancel;
            Close();
        };
        Controls.Add(btnCancel);

        Shown += async (s, e) =>
        {
            SetForegroundWindow(Handle);
            _txtPin.Focus();
            await RefreshKeyTelemetryAsync();
        };
    }

    private async Task RefreshKeyTelemetryAsync()
    {
        try
        {
            var sg = await _client.GetSecureGuardStatusAsync();
            var dev = await _client.DetectDeviceAsync();
            if (IsDisposed) return;

            string port = string.IsNullOrEmpty(dev.Port) ? "COM7" : dev.Port;
            _lblAttempts.Text = $"{dev.Chip} ({port}) • Tentativas: [{sg.RemainingAttempts}/{sg.MaxAttempts}]";
            if (!sg.Provisioned)
            {
                _lblAttempts.Text = $"{port} • Não provisionada (defina novo PIN)";
                _lblAttempts.ForeColor = ColorCyan;
            }
            else if (sg.RemainingAttempts <= 2)
            {
                _lblAttempts.ForeColor = ColorCoral;
            }
        }
        catch { }
    }

    private async Task SubmitPinAsync()
    {
        if (_isBusy) return;
        string pin = _txtPin.Text.Trim();
        if (string.IsNullOrEmpty(pin))
        {
            _lblStatusMsg.Text = "Digite o PIN numérico!";
            _lblStatusMsg.ForeColor = ColorAmber;
            return;
        }

        _isBusy = true;
        _lblStatusMsg.Text = "Verificando com a hardwallet física...";
        _lblStatusMsg.ForeColor = ColorCyan;
        _btnSubmit.Enabled = false;

        EnteredPin = pin;

        if (_performHardwareUnlock)
        {
            bool ok = await _client.UnlockSecureGuardAsync(pin);
            if (ok)
            {
                _lblStatusMsg.Text = "✓ Hardware Desbloqueado com Sucesso!";
                _lblStatusMsg.ForeColor = ColorEmerald;
                await Task.Delay(350);
                DialogResult = DialogResult.OK;
                Close();
                return;
            }
            else
            {
                // Failed attempt
                await RefreshKeyTelemetryAsync();
                var sg = await _client.GetSecureGuardStatusAsync();
                _lblStatusMsg.Text = $"PIN incorreto! Restam {sg.RemainingAttempts} tentativa(s).";
                _lblStatusMsg.ForeColor = ColorCoral;
                _txtPin.Text = "";
                _txtPin.Focus();
                _isBusy = false;
                _btnSubmit.Enabled = true;
                return;
            }
        }
        else
        {
            // Just returning the PIN to the caller
            DialogResult = DialogResult.OK;
            Close();
        }
    }

    public static Task<bool> PromptAndUnlockAsync(
        HardwareBridgeClient client,
        IWin32Window? owner = null,
        string reason = "System Request: Hardware Access",
        string subtitle = "Digite o PIN para desbloquear a sessão na hardwallet.")
    {
        using var dlg = new PinSessionDialog(client, reason, subtitle, performHardwareUnlock: true);
        var res = owner != null ? dlg.ShowDialog(owner) : dlg.ShowDialog();
        return Task.FromResult(res == DialogResult.OK);
    }

    public static Task<string?> PromptPinForActionAsync(
        HardwareBridgeClient client,
        IWin32Window? owner = null,
        string reason = "System Request",
        string subtitle = "Digite o PIN da hardwallet:")
    {
        using var dlg = new PinSessionDialog(client, reason, subtitle, performHardwareUnlock: false);
        var res = owner != null ? dlg.ShowDialog(owner) : dlg.ShowDialog();
        return Task.FromResult(res == DialogResult.OK ? dlg.EnteredPin : null);
    }
}
