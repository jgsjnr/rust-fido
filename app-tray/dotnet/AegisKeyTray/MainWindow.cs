using System.Drawing;
using System.Windows.Forms;

namespace AegisKeyTray;

public class MainWindow : Form
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

    private readonly HardwareBridgeClient _client;
    private readonly SshAgentGuard _sshGuard;

    private DeviceInfo _dev = new();
    private SecureGuardStatus _sg = new();
    private string _activeTab = "sg";

    private Label _lblDeviceName = null!;
    private Label _lblConnBadge = null!;
    private Panel _contentPanel = null!;
    private Button _btnNavSg = null!;
    private Button _btnNavVault = null!;
    private Button _btnNavTotp = null!;
    private Button _btnNavSsh = null!;

    public MainWindow(HardwareBridgeClient client, SshAgentGuard sshGuard)
    {
        _client = client;
        _sshGuard = sshGuard;

        InitializeComponent();
        _ = RefreshDataAsync();
    }

    private void InitializeComponent()
    {
        Text = I18n.T("app_title");
        Size = new Size(640, 740);
        MinimumSize = new Size(580, 680);
        BackColor = ColorBg;
        ForeColor = ColorTextPrimary;
        Font = new Font("Segoe UI", 9F, FontStyle.Regular);
        StartPosition = FormStartPosition.CenterScreen;

        // Header Panel
        var headerPanel = new Panel { Dock = DockStyle.Top, Height = 105, BackColor = ColorBg, Padding = new Padding(20, 12, 20, 8) };

        var topRow = new Panel { Dock = DockStyle.Top, Height = 42, BackColor = ColorBg };
        var lblTitle = new Label { Text = I18n.T("app_title"), Font = new Font("Segoe UI", 15F, FontStyle.Bold), ForeColor = ColorTextPrimary, AutoSize = true, Location = new Point(0, 0) };
        var btnLang = new Button
        {
            Text = "EN / PT",
            Font = new Font("Segoe UI", 8F, FontStyle.Bold),
            ForeColor = ColorCyan,
            BackColor = ColorInputBg,
            FlatStyle = FlatStyle.Flat,
            Size = new Size(70, 28),
            Location = new Point(510, 5),
            Cursor = Cursors.Hand
        };
        btnLang.FlatAppearance.BorderSize = 0;
        btnLang.Click += (s, e) =>
        {
            I18n.CurrentLanguage = I18n.CurrentLanguage == "en" ? "pt" : "en";
            lblTitle.Text = I18n.T("app_title");
            _btnNavSg.Text = I18n.T("sg_title");
            _btnNavVault.Text = I18n.T("vault_title");
            _btnNavTotp.Text = I18n.T("totp_title");
            _btnNavSsh.Text = I18n.T("ssh_title");
            RenderTab();
        };

        topRow.Controls.Add(lblTitle);
        topRow.Controls.Add(btnLang);

        // Banner Card
        var banner = new Panel
        {
            Dock = DockStyle.Bottom,
            Height = 44,
            BackColor = ColorCard,
            Padding = new Padding(12, 10, 12, 10)
        };
        _lblDeviceName = new Label
        {
            Text = "ESP32-S3 (COM7 / USB 0x303A:0xAE61)",
            Font = new Font("Segoe UI", 9.5F, FontStyle.Bold),
            ForeColor = ColorTextPrimary,
            AutoSize = true,
            Location = new Point(12, 12)
        };
        _lblConnBadge = new Label
        {
            Text = "CONNECTING...",
            Font = new Font("Segoe UI", 8F, FontStyle.Bold),
            ForeColor = ColorAmber,
            BackColor = ColorInputBg,
            Size = new Size(110, 24),
            TextAlign = ContentAlignment.MiddleCenter,
            Location = new Point(470, 10)
        };
        banner.Controls.Add(_lblDeviceName);
        banner.Controls.Add(_lblConnBadge);

        headerPanel.Controls.Add(topRow);
        headerPanel.Controls.Add(banner);

        // Nav Bar
        var navBar = new Panel { Dock = DockStyle.Top, Height = 40, BackColor = ColorBg, Padding = new Padding(20, 4, 20, 4) };
        _btnNavSg = CreateNavButton(I18n.T("sg_title"), "sg", 0);
        _btnNavVault = CreateNavButton(I18n.T("vault_title"), "vault", 130);
        _btnNavTotp = CreateNavButton(I18n.T("totp_title"), "totp", 260);
        _btnNavSsh = CreateNavButton(I18n.T("ssh_title"), "ssh", 390);

        navBar.Controls.AddRange(new Control[] { _btnNavSg, _btnNavVault, _btnNavTotp, _btnNavSsh });

        // Content Area
        _contentPanel = new Panel { Dock = DockStyle.Fill, BackColor = ColorBg, Padding = new Padding(20, 10, 20, 20), AutoScroll = true };

        Controls.Add(_contentPanel);
        Controls.Add(navBar);
        Controls.Add(headerPanel);

        // Intercept close to minimize to system tray
        FormClosing += (s, e) =>
        {
            if (e.CloseReason == CloseReason.UserClosing)
            {
                e.Cancel = true;
                Hide();
            }
        };

        RenderTab();
    }

    private Button CreateNavButton(string text, string tabId, int x)
    {
        var btn = new Button
        {
            Text = text,
            Tag = tabId,
            Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
            ForeColor = _activeTab == tabId ? ColorCyan : ColorTextMuted,
            BackColor = _activeTab == tabId ? ColorCard : ColorBg,
            FlatStyle = FlatStyle.Flat,
            Size = new Size(125, 32),
            Location = new Point(20 + x, 4),
            Cursor = Cursors.Hand
        };
        btn.FlatAppearance.BorderSize = 0;
        btn.Click += (s, e) =>
        {
            _activeTab = tabId;
            UpdateNavStyles();
            RenderTab();
        };
        return btn;
    }

    private void UpdateNavStyles()
    {
        foreach (var btn in new[] { _btnNavSg, _btnNavVault, _btnNavTotp, _btnNavSsh })
        {
            bool sel = (string)btn.Tag! == _activeTab;
            btn.ForeColor = sel ? ColorCyan : ColorTextMuted;
            btn.BackColor = sel ? ColorCard : ColorBg;
        }
    }

    public async Task RefreshDataAsync()
    {
        try
        {
            _dev = await _client.DetectDeviceAsync();
            _sg = await _client.GetSecureGuardStatusAsync();

            if (InvokeRequired)
            {
                Invoke(new Action(ApplyDataUpdates));
            }
            else
            {
                ApplyDataUpdates();
            }
        }
        catch { }
    }

    private void ApplyDataUpdates()
    {
        _lblDeviceName.Text = $"{_dev.Product} ({_dev.Port})";
        if (_dev.Connected)
        {
            _lblConnBadge.Text = I18n.T("connected");
            _lblConnBadge.ForeColor = ColorEmerald;
        }
        else
        {
            _lblConnBadge.Text = I18n.T("disconnected");
            _lblConnBadge.ForeColor = ColorCoral;
        }
        RenderTab();
    }

    private void RenderTab()
    {
        _contentPanel.Controls.Clear();
        var card = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = ColorCard,
            Padding = new Padding(18)
        };

        switch (_activeTab)
        {
            case "sg":
                RenderSectionSecureGuard(card);
                break;
            case "vault":
                RenderSectionVault(card);
                break;
            case "totp":
                RenderSectionTotp(card);
                break;
            case "ssh":
                RenderSectionSsh(card);
                break;
        }

        _contentPanel.Controls.Add(card);
    }

    private void RenderSectionSecureGuard(Panel card)
    {
        var lblTitle = new Label { Text = I18n.T("sg_title"), Font = new Font("Segoe UI", 12F, FontStyle.Bold), ForeColor = ColorTextPrimary, AutoSize = true, Location = new Point(16, 16) };
        card.Controls.Add(lblTitle);

        var lblStatus = new Label { Text = $"{I18n.T("sg_status_label")} {_sg.StateName.ToUpper()}", Font = new Font("Segoe UI", 10F, FontStyle.Bold), ForeColor = _sg.Unlocked ? ColorEmerald : ColorAmber, AutoSize = true, Location = new Point(16, 52) };
        card.Controls.Add(lblStatus);

        var lblAttempts = new Label { Text = $"{I18n.T("sg_attempts_label")} [{_sg.RemainingAttempts}/{_sg.MaxAttempts}]", Font = new Font("Segoe UI", 9F), ForeColor = ColorTextMuted, AutoSize = true, Location = new Point(16, 80) };
        card.Controls.Add(lblAttempts);

        int remSec = Math.Max(0, _sg.SessionRemainingMs / 1000);
        string timeStr = _sg.Unlocked ? $"{remSec / 60:D2}:{remSec % 60:D2}" : "--:--";
        var lblSession = new Label { Text = $"{I18n.T("sg_session_label")} {timeStr}", Font = new Font("Segoe UI", 9F), ForeColor = ColorCyan, AutoSize = true, Location = new Point(16, 105) };
        card.Controls.Add(lblSession);

        if (!_sg.Unlocked)
        {
            var txtPin = new TextBox { PasswordChar = '*', Font = new Font("Segoe UI", 11F), BackColor = ColorInputBg, ForeColor = ColorTextPrimary, BorderStyle = BorderStyle.None, Size = new Size(140, 28), Location = new Point(16, 145) };
            var btnUnlock = new Button { Text = I18n.T("sg_btn_unlock"), Font = new Font("Segoe UI", 9F, FontStyle.Bold), BackColor = ColorCyan, ForeColor = Color.Black, FlatStyle = FlatStyle.Flat, Size = new Size(160, 30), Location = new Point(165, 144), Cursor = Cursors.Hand };
            btnUnlock.FlatAppearance.BorderSize = 0;
            btnUnlock.Click += async (s, e) =>
            {
                if (string.IsNullOrWhiteSpace(txtPin.Text)) return;
                bool ok = await _client.UnlockSecureGuardAsync(txtPin.Text.Trim());
                if (ok) await RefreshDataAsync();
            };
            card.Controls.Add(txtPin);
            card.Controls.Add(btnUnlock);
        }
        else
        {
            var btnLock = new Button { Text = I18n.T("sg_btn_lock"), Font = new Font("Segoe UI", 9F, FontStyle.Bold), BackColor = ColorCoral, ForeColor = Color.White, FlatStyle = FlatStyle.Flat, Size = new Size(160, 32), Location = new Point(16, 145), Cursor = Cursors.Hand };
            btnLock.FlatAppearance.BorderSize = 0;
            btnLock.Click += async (s, e) =>
            {
                await _client.LockSecureGuardAsync();
                await RefreshDataAsync();
            };
            card.Controls.Add(btnLock);
        }
    }

    private void RenderSectionVault(Panel card)
    {
        var lblTitle = new Label { Text = I18n.T("vault_title"), Font = new Font("Segoe UI", 12F, FontStyle.Bold), ForeColor = ColorTextPrimary, AutoSize = true, Location = new Point(16, 16) };
        card.Controls.Add(lblTitle);

        if (!_sg.Unlocked)
        {
            var banner = new Panel { Size = new Size(card.Width - 40, 80), Location = new Point(16, 60), BackColor = ColorInputBg };
            var lblBanner = new Label { Text = I18n.T("vault_locked_banner"), Font = new Font("Segoe UI", 10F, FontStyle.Bold), ForeColor = ColorAmber, AutoSize = true, Location = new Point(14, 25) };
            banner.Controls.Add(lblBanner);
            card.Controls.Add(banner);
            return;
        }

        var lblMsg = new Label { Text = "Hardware keys unlocked and accessible.", Font = new Font("Segoe UI", 9F), ForeColor = ColorEmerald, AutoSize = true, Location = new Point(16, 55) };
        card.Controls.Add(lblMsg);
    }

    private void RenderSectionTotp(Panel card)
    {
        var lblTitle = new Label { Text = I18n.T("totp_title"), Font = new Font("Segoe UI", 12F, FontStyle.Bold), ForeColor = ColorTextPrimary, AutoSize = true, Location = new Point(16, 16) };
        var lblSub = new Label { Text = I18n.T("totp_subtitle"), Font = new Font("Segoe UI", 8F), ForeColor = ColorTextMuted, AutoSize = true, Location = new Point(16, 42) };
        card.Controls.Add(lblTitle);
        card.Controls.Add(lblSub);
    }

    private void RenderSectionSsh(Panel card)
    {
        var lblTitle = new Label { Text = I18n.T("ssh_title"), Font = new Font("Segoe UI", 12F, FontStyle.Bold), ForeColor = ColorTextPrimary, AutoSize = true, Location = new Point(16, 16) };
        var lblSub = new Label { Text = I18n.T("ssh_subtitle"), Font = new Font("Segoe UI", 8F), ForeColor = ColorTextMuted, AutoSize = true, Location = new Point(16, 42) };
        card.Controls.Add(lblTitle);
        card.Controls.Add(lblSub);

        bool isActive = _sg.Unlocked && _dev.Connected;
        var banner = new Panel { Size = new Size(card.Width - 40, 60), Location = new Point(16, 70), BackColor = ColorInputBg };
        var lblBanner = new Label
        {
            Text = isActive ? I18n.T("ssh_status_active") : I18n.T("ssh_status_inactive"),
            Font = new Font("Segoe UI", 9F, FontStyle.Bold),
            ForeColor = isActive ? ColorEmerald : ColorAmber,
            AutoSize = true,
            Location = new Point(10, 18)
        };
        banner.Controls.Add(lblBanner);
        card.Controls.Add(banner);

        var (count, msg) = _sshGuard.GetAgentIdentitiesCount();
        var lblCount = new Label { Text = $"Identities in ssh-agent: {count} ({msg})", Font = new Font("Segoe UI", 9F), ForeColor = ColorCyan, AutoSize = true, Location = new Point(16, 145) };
        card.Controls.Add(lblCount);

        var btnPurge = new Button { Text = I18n.T("ssh_btn_purge"), Font = new Font("Segoe UI", 8.5F, FontStyle.Bold), BackColor = ColorCoral, ForeColor = Color.White, FlatStyle = FlatStyle.Flat, Size = new Size(180, 30), Location = new Point(16, 180), Cursor = Cursors.Hand };
        btnPurge.FlatAppearance.BorderSize = 0;
        btnPurge.Click += (s, e) =>
        {
            _sshGuard.PurgeSshAgent();
            RenderTab();
        };

        var btnFido = new Button { Text = I18n.T("ssh_btn_load_fido2"), Font = new Font("Segoe UI", 8.5F, FontStyle.Bold), BackColor = ColorCyan, ForeColor = Color.Black, FlatStyle = FlatStyle.Flat, Size = new Size(200, 30), Location = new Point(205, 180), Cursor = Cursors.Hand };
        btnFido.FlatAppearance.BorderSize = 0;
        btnFido.Click += (s, e) =>
        {
            _sshGuard.LoadResidentFido2Keys();
            RenderTab();
        };

        card.Controls.Add(btnPurge);
        card.Controls.Add(btnFido);
    }
}
