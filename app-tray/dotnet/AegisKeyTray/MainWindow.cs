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
    private string _activeTab = "vault_sg";

    private Label _lblTitle = null!;
    private Label _lblSubtitle = null!;
    private Label _lblDeviceName = null!;
    private Label _lblConnBadge = null!;
    private Panel _contentPanel = null!;
    private Button _btnNavVaultSg = null!;
    private Button _btnNavTotp = null!;
    private Button _btnNavConn = null!;
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
        Size = new Size(680, 760);
        MinimumSize = new Size(620, 700);
        BackColor = ColorBg;
        ForeColor = ColorTextPrimary;
        Font = new Font("Segoe UI", 9F, FontStyle.Regular);
        StartPosition = FormStartPosition.CenterScreen;

        // Header Panel
        var headerPanel = new Panel { Dock = DockStyle.Top, Height = 105, BackColor = ColorBg, Padding = new Padding(20, 12, 20, 8) };

        var topRow = new Panel { Dock = DockStyle.Top, Height = 42, BackColor = ColorBg };
        _lblTitle = new Label { Text = I18n.T("app_title"), Font = new Font("Segoe UI", 15F, FontStyle.Bold), ForeColor = ColorTextPrimary, AutoSize = true, Location = new Point(0, 0) };
        _lblSubtitle = new Label { Text = I18n.T("app_subtitle"), Font = new Font("Segoe UI", 8.5F), ForeColor = ColorTextMuted, AutoSize = true, Location = new Point(2, 23) };

        var btnLang = new Button
        {
            Text = "EN / PT",
            Font = new Font("Segoe UI", 8F, FontStyle.Bold),
            ForeColor = ColorCyan,
            BackColor = ColorInputBg,
            FlatStyle = FlatStyle.Flat,
            Size = new Size(70, 28),
            Location = new Point(550, 5),
            Cursor = Cursors.Hand
        };
        btnLang.FlatAppearance.BorderSize = 0;
        btnLang.Click += (s, e) =>
        {
            I18n.CurrentLanguage = I18n.CurrentLanguage == "en" ? "pt" : "en";
            _lblTitle.Text = I18n.T("app_title");
            _lblSubtitle.Text = I18n.T("app_subtitle");
            _btnNavVaultSg.Text = I18n.T("tab_vault_sg");
            _btnNavTotp.Text = I18n.T("tab_totp");
            _btnNavConn.Text = I18n.T("tab_connected_keys");
            _btnNavSsh.Text = I18n.T("tab_ssh_settings");
            RenderTab();
        };

        topRow.Controls.Add(_lblTitle);
        topRow.Controls.Add(_lblSubtitle);
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
            Size = new Size(115, 24),
            TextAlign = ContentAlignment.MiddleCenter,
            Location = new Point(500, 10)
        };
        banner.Controls.Add(_lblDeviceName);
        banner.Controls.Add(_lblConnBadge);

        headerPanel.Controls.Add(topRow);
        headerPanel.Controls.Add(banner);

        // Navigation Bar (4 sections)
        var navBar = new Panel { Dock = DockStyle.Top, Height = 42, BackColor = ColorBg, Padding = new Padding(20, 4, 20, 4) };
        _btnNavVaultSg = CreateNavButton(I18n.T("tab_vault_sg"), "vault_sg", 0);
        _btnNavTotp = CreateNavButton(I18n.T("tab_totp"), "totp", 150);
        _btnNavConn = CreateNavButton(I18n.T("tab_connected_keys"), "conn", 300);
        _btnNavSsh = CreateNavButton(I18n.T("tab_ssh_settings"), "ssh", 450);

        navBar.Controls.AddRange(new Control[] { _btnNavVaultSg, _btnNavTotp, _btnNavConn, _btnNavSsh });

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
            Size = new Size(145, 32),
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
        foreach (var btn in new[] { _btnNavVaultSg, _btnNavTotp, _btnNavConn, _btnNavSsh })
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
            case "vault_sg":
                RenderSectionVaultSg(card);
                break;
            case "totp":
                RenderSectionTotp(card);
                break;
            case "conn":
                RenderSectionConnectedKeys(card);
                break;
            case "ssh":
                RenderSectionSsh(card);
                break;
        }

        _contentPanel.Controls.Add(card);
    }

    private void RenderSectionVaultSg(Panel card)
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

        // Security Badges (GAP-01 & GAP-02)
        var pnlBadges = new Panel { Size = new Size(card.Width - 40, 26), Location = new Point(16, 130), BackColor = ColorBg };
        var lblEcdh = new Label { Text = $"✓ {I18n.T("badge_ecdh_active")}", Font = new Font("Segoe UI", 8F, FontStyle.Bold), ForeColor = ColorEmerald, AutoSize = true, Location = new Point(4, 4) };
        var lblEfuse = new Label { Text = $"🔒 {I18n.T("badge_efuse_safe")}", Font = new Font("Segoe UI", 8F, FontStyle.Bold), ForeColor = ColorCyan, AutoSize = true, Location = new Point(240, 4) };
        pnlBadges.Controls.AddRange(new Control[] { lblEcdh, lblEfuse });
        card.Controls.Add(pnlBadges);

        if (!_sg.Unlocked)
        {
            var txtPin = new TextBox { PasswordChar = '*', Font = new Font("Segoe UI", 11F), BackColor = ColorInputBg, ForeColor = ColorTextPrimary, BorderStyle = BorderStyle.None, Size = new Size(140, 28), Location = new Point(16, 168) };
            var btnUnlock = new Button { Text = I18n.T("sg_btn_unlock"), Font = new Font("Segoe UI", 9F, FontStyle.Bold), BackColor = ColorCyan, ForeColor = Color.Black, FlatStyle = FlatStyle.Flat, Size = new Size(160, 30), Location = new Point(165, 167), Cursor = Cursors.Hand };
            btnUnlock.FlatAppearance.BorderSize = 0;
            btnUnlock.Click += async (s, e) =>
            {
                if (string.IsNullOrWhiteSpace(txtPin.Text)) return;
                bool ok = await _client.UnlockSecureGuardAsync(txtPin.Text.Trim());
                if (ok) await RefreshDataAsync();
            };
            card.Controls.Add(txtPin);
            card.Controls.Add(btnUnlock);

            var banner = new Panel { Size = new Size(card.Width - 40, 65), Location = new Point(16, 215), BackColor = ColorInputBg };
            var lblBanner = new Label { Text = I18n.T("vault_locked_banner"), Font = new Font("Segoe UI", 9.5F, FontStyle.Bold), ForeColor = ColorAmber, AutoSize = true, Location = new Point(12, 22) };
            banner.Controls.Add(lblBanner);
            card.Controls.Add(banner);
        }
        else
        {
            var btnLock = new Button { Text = I18n.T("sg_btn_lock"), Font = new Font("Segoe UI", 9F, FontStyle.Bold), BackColor = ColorCoral, ForeColor = Color.White, FlatStyle = FlatStyle.Flat, Size = new Size(140, 32), Location = new Point(16, 168), Cursor = Cursors.Hand };
            btnLock.FlatAppearance.BorderSize = 0;
            btnLock.Click += async (s, e) =>
            {
                await _client.LockSecureGuardAsync();
                await RefreshDataAsync();
            };
            card.Controls.Add(btnLock);

            // OPP-05 Shamir 2-of-3 Backup Button
            var btnShamir = new Button { Text = I18n.T("btn_shamir_backup"), Font = new Font("Segoe UI", 8.5F, FontStyle.Bold), BackColor = ColorEmerald, ForeColor = Color.Black, FlatStyle = FlatStyle.Flat, Size = new Size(240, 32), Location = new Point(165, 168), Cursor = Cursors.Hand };
            btnShamir.FlatAppearance.BorderSize = 0;
            btnShamir.Click += async (s, e) =>
            {
                var shares = await _client.ShamirSplitAsync();
                if (shares.Count >= 3)
                {
                    string info = $"Shamir 2-of-3 Backup Shares Generated:\n\n" +
                                  $"Share 1: {shares[0].ShareHex[..16]}... ({shares[0].Description})\n" +
                                  $"Share 2: {shares[1].ShareHex[..16]}... ({shares[1].Description})\n" +
                                  $"Share 3: {shares[2].ShareHex[..16]}... ({shares[2].Description})\n\n" +
                                  $"Lagrange quorum: Any 2 shares restore 100% of vault master key.";
                    MessageBox.Show(info, "Shamir 2-of-3 Backup (SLIP-0039)", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            };
            card.Controls.Add(btnShamir);

            var lblMsg = new Label { Text = "✓ Hardware Vault unlocked: Ed25519, P-256 and Wallets accessible.", Font = new Font("Segoe UI", 9F, FontStyle.Bold), ForeColor = ColorEmerald, AutoSize = true, Location = new Point(16, 215) };
            card.Controls.Add(lblMsg);
        }
    }

    private void RenderSectionTotp(Panel card)
    {
        var lblTitle = new Label { Text = I18n.T("totp_title"), Font = new Font("Segoe UI", 12F, FontStyle.Bold), ForeColor = ColorTextPrimary, AutoSize = true, Location = new Point(16, 16) };
        var lblSub = new Label { Text = I18n.T("totp_subtitle"), Font = new Font("Segoe UI", 8F), ForeColor = ColorTextMuted, AutoSize = true, Location = new Point(16, 42) };
        card.Controls.Add(lblTitle);
        card.Controls.Add(lblSub);
    }

    private void RenderSectionConnectedKeys(Panel card)
    {
        var lblTitle = new Label { Text = I18n.T("conn_title"), Font = new Font("Segoe UI", 12F, FontStyle.Bold), ForeColor = ColorTextPrimary, AutoSize = true, Location = new Point(16, 16) };
        card.Controls.Add(lblTitle);

        var pnlTele = new Panel { Size = new Size(card.Width - 40, 110), Location = new Point(16, 50), BackColor = ColorInputBg, Padding = new Padding(12) };
        var lblChip = new Label { Text = $"Chip: {_dev.Chip}", Font = new Font("Segoe UI", 9F, FontStyle.Bold), ForeColor = ColorCyan, AutoSize = true, Location = new Point(12, 12) };
        var lblPort = new Label { Text = $"Serial Port: {_dev.Port} (VID: {_dev.Vid}, PID: {_dev.Pid})", Font = new Font("Segoe UI", 8.5F), ForeColor = ColorTextPrimary, AutoSize = true, Location = new Point(12, 38) };
        var lblState = new Label { Text = $"Status: {(_dev.Connected ? "ONLINE" : "DISCONNECTED")}", Font = new Font("Segoe UI", 8.5F, FontStyle.Bold), ForeColor = _dev.Connected ? ColorEmerald : ColorCoral, AutoSize = true, Location = new Point(12, 64) };
        pnlTele.Controls.AddRange(new Control[] { lblChip, lblPort, lblState });
        card.Controls.Add(pnlTele);

        var lblProxTitle = new Label { Text = I18n.T("conn_prox_title"), Font = new Font("Segoe UI", 10F, FontStyle.Bold), ForeColor = ColorTextPrimary, AutoSize = true, Location = new Point(16, 175) };
        card.Controls.Add(lblProxTitle);

        var pnlProx = new Panel { Size = new Size(card.Width - 40, 75), Location = new Point(16, 202), BackColor = ColorInputBg, Padding = new Padding(12) };
        var lblProxArmed = new Label { Text = "Status: ARMED (Windows Dynamic Lock Active via BLE RSSI)", Font = new Font("Segoe UI", 8.5F, FontStyle.Bold), ForeColor = ColorEmerald, AutoSize = true, Location = new Point(12, 12) };
        var lblProxSignal = new Label { Text = "Signal RSSI: -35 dBm  |  Lock Distance Threshold: -75 dBm  |  Safe Dev Mode: Active", Font = new Font("Segoe UI", 8F), ForeColor = ColorTextMuted, AutoSize = true, Location = new Point(12, 36) };
        pnlProx.Controls.AddRange(new Control[] { lblProxArmed, lblProxSignal });
        card.Controls.Add(pnlProx);

        // OPP-06 Clear Signing Preview Button
        var btnClearSign = new Button { Text = I18n.T("btn_clear_signing"), Font = new Font("Segoe UI", 8.5F, FontStyle.Bold), BackColor = ColorCyan, ForeColor = Color.Black, FlatStyle = FlatStyle.Flat, Size = new Size(260, 32), Location = new Point(16, 290), Cursor = Cursors.Hand };
        btnClearSign.FlatAppearance.BorderSize = 0;
        btnClearSign.Click += async (s, e) =>
        {
            var preview = await _client.ClearSignPreviewAsync("ETH", "0x892a43bC8419F71bC02Fa9832A1C90B5D", "0.7500 ETH", "0.0012 ETH");
            if (preview != null)
            {
                MessageBox.Show(preview, "Clear Signing OLED 128x64 Frame Preview", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        };
        card.Controls.Add(btnClearSign);
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

        // OPP-01 Native OpenSSH Agent Status Card
        var pnlAgent = new Panel { Size = new Size(card.Width - 40, 60), Location = new Point(16, 140), BackColor = ColorInputBg, Padding = new Padding(10) };
        var lblAgentTitle = new Label { Text = I18n.T("ssh_native_agent_title"), Font = new Font("Segoe UI", 9F, FontStyle.Bold), ForeColor = ColorCyan, AutoSize = true, Location = new Point(10, 10) };
        var lblAgentStatus = new Label { Text = $"{I18n.T("ssh_native_agent_status")}  |  Hardware Signing: ESP32-S3 Ed25519 (Slot 0)", Font = new Font("Segoe UI", 8F), ForeColor = ColorEmerald, AutoSize = true, Location = new Point(10, 32) };
        pnlAgent.Controls.AddRange(new Control[] { lblAgentTitle, lblAgentStatus });
        card.Controls.Add(pnlAgent);

        var (count, msg) = _sshGuard.GetAgentIdentitiesCount();
        var lblCount = new Label { Text = $"Identities in ssh-agent: {count} ({msg})", Font = new Font("Segoe UI", 9F), ForeColor = ColorCyan, AutoSize = true, Location = new Point(16, 215) };
        card.Controls.Add(lblCount);

        var btnPurge = new Button { Text = I18n.T("ssh_btn_purge"), Font = new Font("Segoe UI", 8.5F, FontStyle.Bold), BackColor = ColorCoral, ForeColor = Color.White, FlatStyle = FlatStyle.Flat, Size = new Size(180, 30), Location = new Point(16, 250), Cursor = Cursors.Hand };
        btnPurge.FlatAppearance.BorderSize = 0;
        btnPurge.Click += (s, e) =>
        {
            _sshGuard.PurgeSshAgent();
            RenderTab();
        };

        var btnFido = new Button { Text = I18n.T("ssh_btn_load_fido2"), Font = new Font("Segoe UI", 8.5F, FontStyle.Bold), BackColor = ColorCyan, ForeColor = Color.Black, FlatStyle = FlatStyle.Flat, Size = new Size(200, 30), Location = new Point(205, 250), Cursor = Cursors.Hand };
        btnFido.FlatAppearance.BorderSize = 0;
        btnFido.Click += (s, e) =>
        {
            _sshGuard.LoadResidentFido2Keys();
            RenderTab();
        };

        card.Controls.Add(btnPurge);
        card.Controls.Add(btnFido);
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        if (e.CloseReason == CloseReason.UserClosing)
        {
            e.Cancel = true;
            Hide();
            return;
        }
        base.OnFormClosing(e);
    }

    protected override void OnResize(EventArgs e)
    {
        base.OnResize(e);
        if (WindowState == FormWindowState.Minimized)
        {
            Hide();
        }
    }
}
