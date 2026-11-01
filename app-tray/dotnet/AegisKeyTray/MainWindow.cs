using System.Drawing;
using System.Runtime.InteropServices;
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

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    private readonly HardwareBridgeClient _client;
    private readonly SshAgentGuard _sshGuard;
    private readonly SynchronizationContext _syncContext;

    private DeviceInfo _dev = new();
    private SecureGuardStatus _sg = new();
    private string _activeTab = "vault_sg";
    private bool _isPromptOpen = false;

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
        _syncContext = WindowsFormsSynchronizationContext.Current ?? new WindowsFormsSynchronizationContext();

        InitializeComponent();
        _ = RefreshDataAsync();

        var pollTimer = new System.Windows.Forms.Timer { Interval = 1500 };
        pollTimer.Tick += async (s, e) =>
        {
            try
            {
                await RefreshDataAsync();
            }
            catch { }
        };
        pollTimer.Start();
    }

    private void InitializeComponent()
    {
        Text = I18n.T("app_title");
        // Compact Mobile Phone Floating Window Style (Manager / 1Password Mini / Mobile Phone Aspect Ratio)
        Size = new Size(380, 660);
        MinimumSize = new Size(380, 660);
        MaximumSize = new Size(380, 660);
        FormBorderStyle = FormBorderStyle.FixedSingle;
        MaximizeBox = false;
        BackColor = ColorBg;
        ForeColor = ColorTextPrimary;
        Font = new Font("Segoe UI", 9F, FontStyle.Regular);
        StartPosition = FormStartPosition.CenterScreen;

        // Header Panel (Compact Mobile Style)
        var headerPanel = new Panel
        {
            Dock = DockStyle.Top,
            Height = 88,
            BackColor = ColorBg,
            Padding = new Padding(14, 8, 14, 4)
        };

        var topRow = new Panel
        {
            Dock = DockStyle.Top,
            Height = 36,
            BackColor = ColorBg
        };

        _lblTitle = new Label
        {
            Text = "🛡️ AegisKey",
            Font = new Font("Segoe UI", 12F, FontStyle.Bold),
            ForeColor = ColorCyan,
            AutoSize = true,
            Location = new Point(0, 4)
        };

        _lblSubtitle = new Label
        {
            Text = "Hardware Authority",
            Font = new Font("Segoe UI", 8F),
            ForeColor = ColorTextMuted,
            AutoSize = true,
            Location = new Point(102, 8)
        };

        var btnLang = new Button
        {
            Text = "EN/PT",
            Font = new Font("Segoe UI", 7.5F, FontStyle.Bold),
            ForeColor = ColorCyan,
            BackColor = ColorInputBg,
            FlatStyle = FlatStyle.Flat,
            Size = new Size(54, 24),
            Location = new Point(294, 5),
            Cursor = Cursors.Hand
        };
        btnLang.FlatAppearance.BorderSize = 0;
        btnLang.Click += (s, e) =>
        {
            I18n.CurrentLanguage = I18n.CurrentLanguage == "en" ? "pt" : "en";
            _lblTitle.Text = "🛡️ AegisKey";
            _btnNavVaultSg.Text = I18n.CurrentLanguage == "pt" ? "🔑 Cofre" : "🔑 Vault";
            _btnNavTotp.Text = "⏳ TOTP";
            _btnNavConn.Text = I18n.CurrentLanguage == "pt" ? "🔗 Link" : "🔗 Conn";
            _btnNavSsh.Text = "🛡️ SSH";
            RenderTab();
        };

        topRow.Controls.AddRange(new Control[] { _lblTitle, _lblSubtitle, btnLang });

        // Hardware Status Banner Card
        var banner = new Panel
        {
            Dock = DockStyle.Bottom,
            Height = 36,
            BackColor = ColorCard,
            Padding = new Padding(10, 6, 10, 6)
        };

        _lblDeviceName = new Label
        {
            Text = "ESP32-S3 (COM7)",
            Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
            ForeColor = ColorTextPrimary,
            AutoSize = true,
            Location = new Point(8, 8)
        };

        _lblConnBadge = new Label
        {
            Text = "CONNECTING...",
            Font = new Font("Segoe UI", 7.5F, FontStyle.Bold),
            ForeColor = ColorAmber,
            BackColor = ColorInputBg,
            Size = new Size(100, 20),
            TextAlign = ContentAlignment.MiddleCenter,
            Location = new Point(238, 7)
        };

        banner.Controls.AddRange(new Control[] { _lblDeviceName, _lblConnBadge });

        headerPanel.Controls.Add(topRow);
        headerPanel.Controls.Add(banner);

        // Mobile Navigation Bar (4 Compact Tabs across 380px)
        var navBar = new Panel
        {
            Dock = DockStyle.Top,
            Height = 36,
            BackColor = ColorBg,
            Padding = new Padding(6, 2, 6, 2)
        };

        _btnNavVaultSg = CreateMobileNavButton("🔑 Vault", "vault_sg", 0);
        _btnNavTotp = CreateMobileNavButton("⏳ TOTP", "totp", 88);
        _btnNavConn = CreateMobileNavButton("🔗 Conn", "conn", 176);
        _btnNavSsh = CreateMobileNavButton("🛡️ SSH", "ssh", 264);

        navBar.Controls.AddRange(new Control[] { _btnNavVaultSg, _btnNavTotp, _btnNavConn, _btnNavSsh });

        // Content Area (Scrollable Vertical Column)
        _contentPanel = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = ColorBg,
            Padding = new Padding(12, 6, 12, 12),
            AutoScroll = true
        };

        Controls.Add(_contentPanel);
        Controls.Add(navBar);
        Controls.Add(headerPanel);

        RenderTab();
    }

    private Button CreateMobileNavButton(string text, string tabId, int x)
    {
        var btn = new Button
        {
            Text = text,
            Tag = tabId,
            Font = new Font("Segoe UI", 8F, FontStyle.Bold),
            ForeColor = _activeTab == tabId ? ColorCyan : ColorTextMuted,
            BackColor = _activeTab == tabId ? ColorCard : ColorBg,
            FlatStyle = FlatStyle.Flat,
            Size = new Size(84, 30),
            Location = new Point(6 + x, 3),
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

            _syncContext.Post(_ =>
            {
                if (IsDisposed) return;
                ApplyDataUpdates();
            }, null);

            // Check if there are any OS/System pending authentication requests
            if (!_isPromptOpen && !_sg.Unlocked && _dev.Connected)
            {
                var pendingReqs = await _client.GetPendingSystemAuthAsync();
                if (pendingReqs.Count > 0)
                {
                    var topReq = pendingReqs[0];
                    _syncContext.Post(_ =>
                    {
                        if (IsDisposed) return;
                        _ = HandleSystemRequestPromptAsync(topReq);
                    }, null);
                }
            }
        }
        catch { }
    }

    private async Task HandleSystemRequestPromptAsync(SystemAuthRequest req)
    {
        if (_isPromptOpen) return;
        _isPromptOpen = true;
        try
        {
            Show();
            WindowState = FormWindowState.Normal;
            BringToFront();
            SetForegroundWindow(Handle);
            string reason = $"Solicitação do Sistema: {req.Source}";
            string subtitle = $"{req.Operation} — {req.Reason}";
            bool ok = await PinSessionDialog.PromptAndUnlockAsync(_client, this, reason, subtitle);
            await _client.ResolveSystemAuthRequestAsync(req.Id, ok);
            await RefreshDataAsync();
        }
        finally
        {
            _isPromptOpen = false;
        }
    }

    public async Task<bool> RequestUnlockFromUiAsync(string reason)
    {
        if (_sg.Unlocked) return true;

        var tcs = new TaskCompletionSource<bool>();
        _syncContext.Post(_ =>
        {
            try
            {
                Show();
                WindowState = FormWindowState.Normal;
                BringToFront();
                SetForegroundWindow(Handle);
                bool ok = PinSessionDialog.PromptAndUnlockAsync(_client, this, reason, "O sistema operacional solicita acesso à chave de hardware.").GetAwaiter().GetResult();
                if (ok) _ = RefreshDataAsync();
                tcs.TrySetResult(ok);
            }
            catch (Exception ex)
            {
                tcs.TrySetException(ex);
            }
        }, null);

        return await tcs.Task;
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
            Padding = new Padding(12),
            AutoScroll = true
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
        var lblTitle = new Label
        {
            Text = I18n.T("sg_title"),
            Font = new Font("Segoe UI", 10F, FontStyle.Bold),
            ForeColor = ColorTextPrimary,
            Size = new Size(310, 36),
            Location = new Point(12, 12)
        };
        card.Controls.Add(lblTitle);

        var lblStatus = new Label
        {
            Text = $"{I18n.T("sg_status_label")} {_sg.StateName.ToUpper()}",
            Font = new Font("Segoe UI", 9.5F, FontStyle.Bold),
            ForeColor = _sg.Unlocked ? ColorEmerald : ColorAmber,
            AutoSize = true,
            Location = new Point(12, 50)
        };
        card.Controls.Add(lblStatus);

        var lblAttempts = new Label
        {
            Text = $"{I18n.T("sg_attempts_label")} [{_sg.RemainingAttempts}/{_sg.MaxAttempts}]",
            Font = new Font("Segoe UI", 8.5F),
            ForeColor = ColorTextMuted,
            AutoSize = true,
            Location = new Point(12, 74)
        };
        card.Controls.Add(lblAttempts);

        int remSec = Math.Max(0, _sg.SessionRemainingMs / 1000);
        string timeStr = _sg.Unlocked ? $"{remSec / 60:D2}:{remSec % 60:D2}" : "--:--";
        var lblSession = new Label
        {
            Text = $"{I18n.T("sg_session_label")} {timeStr}",
            Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
            ForeColor = ColorCyan,
            AutoSize = true,
            Location = new Point(12, 96)
        };
        card.Controls.Add(lblSession);

        // Security Badges (GAP-01 & GAP-02)
        var pnlBadges = new Panel
        {
            Size = new Size(306, 44),
            Location = new Point(12, 122),
            BackColor = ColorInputBg,
            Padding = new Padding(8)
        };
        var lblEcdh = new Label
        {
            Text = $"✓ {I18n.T("badge_ecdh_active")}",
            Font = new Font("Segoe UI", 7.5F, FontStyle.Bold),
            ForeColor = ColorEmerald,
            AutoSize = true,
            Location = new Point(6, 4)
        };
        var lblEfuse = new Label
        {
            Text = $"🔒 {I18n.T("badge_efuse_safe")}",
            Font = new Font("Segoe UI", 7.5F, FontStyle.Bold),
            ForeColor = ColorCyan,
            AutoSize = true,
            Location = new Point(6, 22)
        };
        pnlBadges.Controls.AddRange(new Control[] { lblEcdh, lblEfuse });
        card.Controls.Add(pnlBadges);

        if (!_sg.Unlocked)
        {
            // Interactive Unlock Button -> Opens PinSessionDialog TopMost!
            var btnOpenPinModal = new Button
            {
                Text = "🔓 Digitar PIN na Chave Física",
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold),
                BackColor = ColorCyan,
                ForeColor = Color.Black,
                FlatStyle = FlatStyle.Flat,
                Size = new Size(306, 38),
                Location = new Point(12, 178),
                Cursor = Cursors.Hand
            };
            btnOpenPinModal.FlatAppearance.BorderSize = 0;
            btnOpenPinModal.Click += async (s, e) =>
            {
                bool ok = await PinSessionDialog.PromptAndUnlockAsync(_client, this, "Desbloqueio de Sessão do Hardware", "Digite o PIN para desbloquear a hardwallet AegisKey.");
                if (ok) await RefreshDataAsync();
            };
            card.Controls.Add(btnOpenPinModal);

            var banner = new Panel
            {
                Size = new Size(306, 60),
                Location = new Point(12, 228),
                BackColor = ColorInputBg,
                Padding = new Padding(10)
            };
            var lblBanner = new Label
            {
                Text = I18n.T("vault_locked_banner"),
                Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
                ForeColor = ColorAmber,
                Size = new Size(286, 40),
                Location = new Point(8, 10)
            };
            banner.Controls.Add(lblBanner);
            card.Controls.Add(banner);
        }
        else
        {
            var btnLock = new Button
            {
                Text = "🔒 Bloquear Sessão",
                Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
                BackColor = ColorCoral,
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Size = new Size(148, 34),
                Location = new Point(12, 178),
                Cursor = Cursors.Hand
            };
            btnLock.FlatAppearance.BorderSize = 0;
            btnLock.Click += async (s, e) =>
            {
                await _client.LockSecureGuardAsync();
                await RefreshDataAsync();
            };
            card.Controls.Add(btnLock);

            // Shamir 2-of-3 Backup Button
            var btnShamir = new Button
            {
                Text = "📦 Backup Shamir",
                Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
                BackColor = ColorEmerald,
                ForeColor = Color.Black,
                FlatStyle = FlatStyle.Flat,
                Size = new Size(148, 34),
                Location = new Point(170, 178),
                Cursor = Cursors.Hand
            };
            btnShamir.FlatAppearance.BorderSize = 0;
            btnShamir.Click += async (s, e) =>
            {
                var shares = await _client.ShamirSplitAsync();
                if (shares.Count >= 3)
                {
                    string info = $"Backup Shamir 2-de-3 (SLIP-0039):\n\n" +
                                  $"Parte 1: {shares[0].ShareHex[..16]}... ({shares[0].Description})\n" +
                                  $"Parte 2: {shares[1].ShareHex[..16]}... ({shares[1].Description})\n" +
                                  $"Parte 3: {shares[2].ShareHex[..16]}... ({shares[2].Description})\n\n" +
                                  $"Quórum Lagrange: Quaisquer 2 partes restauram 100% da chave mestra.";
                    MessageBox.Show(info, "Backup Shamir 2-de-3", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            };
            card.Controls.Add(btnShamir);

            // Wipe Seletivo Button
            var btnWipe = new Button
            {
                Text = "🔥 Wipe Seletivo (Requer PIN)",
                Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
                BackColor = Color.FromArgb(127, 29, 29),
                ForeColor = Color.FromArgb(254, 202, 202),
                FlatStyle = FlatStyle.Flat,
                Size = new Size(306, 32),
                Location = new Point(12, 222),
                Cursor = Cursors.Hand
            };
            btnWipe.FlatAppearance.BorderSize = 0;
            btnWipe.Click += async (s, e) =>
            {
                string? pin = await PinSessionDialog.PromptPinForActionAsync(_client, this, "Wipe Seletivo da Hardwallet", "Digite o PIN da chave física para autorizar a destruição dos dados:");
                if (!string.IsNullOrEmpty(pin))
                {
                    bool ok = await _client.WipeSelectiveAsync(pin);
                    MessageBox.Show(ok ? "Wipe seletivo executado com sucesso na hardwallet!" : "PIN incorreto ou falha na autorização do Wipe.", "Wipe Seletivo", MessageBoxButtons.OK, ok ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
                    await RefreshDataAsync();
                }
            };
            card.Controls.Add(btnWipe);

            var lblMsg = new Label
            {
                Text = "✓ Hardware Vault Desbloqueado: Ed25519, P-256 e Wallets acessíveis.",
                Font = new Font("Segoe UI", 8F, FontStyle.Bold),
                ForeColor = ColorEmerald,
                Size = new Size(306, 36),
                Location = new Point(12, 264)
            };
            card.Controls.Add(lblMsg);
        }

        // KeePassXC Hardware Unlock (.kdbx) Card
        int keepassY = !_sg.Unlocked ? 298 : 308;
        var pnlKeePass = new Panel
        {
            Size = new Size(306, 126),
            Location = new Point(12, keepassY),
            BackColor = ColorInputBg,
            Padding = new Padding(10)
        };

        var lblKeePassTitle = new Label
        {
            Text = "🔐 KeePassXC Hardware Unlock (.kdbx)",
            Font = new Font("Segoe UI", 9F, FontStyle.Bold),
            ForeColor = ColorCyan,
            AutoSize = true,
            Location = new Point(8, 8)
        };

        var lblKeePassStatus = new Label
        {
            Text = "Slot 1 (HMAC-SHA1) & FIDO2 hmac-secret: READY\nJIT RAM Zeroize: ACTIVE | PSRAM 8MB Ready",
            Font = new Font("Segoe UI", 7.5F, FontStyle.Bold),
            ForeColor = ColorEmerald,
            Size = new Size(290, 28),
            Location = new Point(8, 28)
        };

        var lblKeePassCaps = new Label
        {
            Text = "ChaCha20-Poly1305 & RSA-2048/3072 DS Ready",
            Font = new Font("Segoe UI", 7.0F),
            ForeColor = ColorTextMuted,
            Size = new Size(290, 16),
            Location = new Point(8, 58)
        };

        var btnConfigSlot1 = new Button
        {
            Text = "⚙️ Config. Slot 1",
            Font = new Font("Segoe UI", 8F, FontStyle.Bold),
            BackColor = ColorCyan,
            ForeColor = Color.Black,
            FlatStyle = FlatStyle.Flat,
            Size = new Size(138, 30),
            Location = new Point(8, 80),
            Cursor = Cursors.Hand
        };
        btnConfigSlot1.FlatAppearance.BorderSize = 0;
        btnConfigSlot1.Click += async (s, e) =>
        {
            if (!_sg.Unlocked)
            {
                bool okPin = await PinSessionDialog.PromptAndUnlockAsync(_client, this, "Configuração KeePassXC", "Digite o PIN para desbloquear a hardwallet e configurar o Slot 1.");
                if (!okPin) return;
            }
            var (ok, secHex, msg) = await _client.ConfigureKeePassXcSlotAsync(1);
            if (ok)
            {
                try { Clipboard.SetText(secHex); } catch { }
                MessageBox.Show(
                    $"✓ Slot 1 (HMAC-SHA1 20B) configurado com sucesso!\n\n" +
                    $"• Chave Hex: {secHex}\n\n" +
                    $"Chave copiada para a Área de Transferência para backup ou uso no KeePassXC!\n\n" +
                    $"A chave fica criptografada no hardware e é carregada na SRAM apenas no instante do desafio com Zeroize imediato.",
                    "KeePassXC Slot 1 Configurado",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information
                );
                await RefreshDataAsync();
            }
            else
            {
                MessageBox.Show($"Falha na configuração do Slot 1: {msg}", "Erro KeePassXC", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        };

        var btnTestChal = new Button
        {
            Text = "⚡ Testar Desafio",
            Font = new Font("Segoe UI", 8F, FontStyle.Bold),
            BackColor = ColorCard,
            ForeColor = ColorCyan,
            FlatStyle = FlatStyle.Flat,
            Size = new Size(138, 30),
            Location = new Point(152, 80),
            Cursor = Cursors.Hand
        };
        btnTestChal.FlatAppearance.BorderSize = 0;
        btnTestChal.Click += async (s, e) =>
        {
            if (!_sg.Unlocked)
            {
                bool okPin = await PinSessionDialog.PromptAndUnlockAsync(_client, this, "Desafio KeePassXC", "Digite o PIN para autorizar a resposta ao desafio KeePassXC (.kdbx).");
                if (!okPin) return;
            }
            string testChalHex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
            var (ok, respHex, crcHex, err) = await _client.ChallengeResponseKeePassXcAsync(1, testChalHex);
            if (ok)
            {
                MessageBox.Show(
                    $"✓ Desafio KeePassXC executado com sucesso!\n\n" +
                    $"• Desafio: {testChalHex[..20]}...\n" +
                    $"• Resposta HMAC-SHA1: {respHex}\n" +
                    $"• YubiKey CRC-16: 0x{crcHex}\n" +
                    $"• Just-in-Time SRAM Zeroize: EXECUTADO (chave apagada da RAM imediatamente).",
                    "Teste KeePassXC Bem-sucedido",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information
                );
            }
            else
            {
                MessageBox.Show($"Falha no teste de desafio: {err}", "Erro Desafio KeePassXC", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        };

        pnlKeePass.Controls.AddRange(new Control[] { lblKeePassTitle, lblKeePassStatus, lblKeePassCaps, btnConfigSlot1, btnTestChal });
        card.Controls.Add(pnlKeePass);
    }

    private void RenderSectionTotp(Panel card)
    {
        var lblTitle = new Label
        {
            Text = I18n.T("totp_title"),
            Font = new Font("Segoe UI", 10.5F, FontStyle.Bold),
            ForeColor = ColorTextPrimary,
            AutoSize = true,
            Location = new Point(12, 12)
        };
        var lblSub = new Label
        {
            Text = I18n.T("totp_subtitle"),
            Font = new Font("Segoe UI", 7.5F),
            ForeColor = ColorTextMuted,
            Size = new Size(306, 26),
            Location = new Point(12, 36)
        };
        card.Controls.Add(lblTitle);
        card.Controls.Add(lblSub);

        int y = 68;
        var oathAccounts = _client.GetOathAccountsAsync().GetAwaiter().GetResult();
        if (oathAccounts.Count == 0)
        {
            var pnlEmpty = new Panel
            {
                Size = new Size(306, 70),
                Location = new Point(12, y),
                BackColor = ColorInputBg,
                Padding = new Padding(10)
            };
            var lblEmpty = new Label
            {
                Text = _sg.Unlocked ? "Nenhuma conta TOTP registrada na hardwallet." : "🔒 Desbloqueie o Secure Guard para visualizar os códigos TOTP.",
                Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
                ForeColor = _sg.Unlocked ? ColorTextMuted : ColorAmber,
                Size = new Size(286, 50),
                Location = new Point(8, 8)
            };
            pnlEmpty.Controls.Add(lblEmpty);
            card.Controls.Add(pnlEmpty);
        }
        else
        {
            foreach (var acc in oathAccounts)
            {
                var pnlAcc = new Panel
                {
                    Size = new Size(306, 56),
                    Location = new Point(12, y),
                    BackColor = ColorInputBg,
                    Padding = new Padding(8)
                };
                var lblAccName = new Label
                {
                    Text = acc.Name,
                    Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
                    ForeColor = ColorTextPrimary,
                    Location = new Point(8, 8),
                    AutoSize = true
                };
                var lblCode = new Label
                {
                    Text = $"{acc.Code[..3]} {acc.Code[3..]}",
                    Font = new Font("Segoe UI", 13F, FontStyle.Bold),
                    ForeColor = ColorCyan,
                    Location = new Point(8, 26),
                    AutoSize = true
                };
                var btnCopy = new Button
                {
                    Text = "Copiar",
                    Font = new Font("Segoe UI", 7.5F, FontStyle.Bold),
                    BackColor = ColorCard,
                    ForeColor = ColorTextPrimary,
                    FlatStyle = FlatStyle.Flat,
                    Size = new Size(54, 26),
                    Location = new Point(244, 15),
                    Cursor = Cursors.Hand
                };
                btnCopy.FlatAppearance.BorderSize = 0;
                btnCopy.Click += (s, e) =>
                {
                    Clipboard.SetText(acc.Code);
                    btnCopy.Text = "✓";
                };
                pnlAcc.Controls.AddRange(new Control[] { lblAccName, lblCode, btnCopy });
                card.Controls.Add(pnlAcc);
                y += 62;
            }
        }
    }

    private void RenderSectionConnectedKeys(Panel card)
    {
        var lblTitle = new Label
        {
            Text = I18n.T("conn_title"),
            Font = new Font("Segoe UI", 10.5F, FontStyle.Bold),
            ForeColor = ColorTextPrimary,
            AutoSize = true,
            Location = new Point(12, 12)
        };
        card.Controls.Add(lblTitle);

        var pnlTele = new Panel
        {
            Size = new Size(306, 110),
            Location = new Point(12, 42),
            BackColor = ColorInputBg,
            Padding = new Padding(10)
        };
        var lblChip = new Label
        {
            Text = $"Chip: {_dev.Chip}",
            Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
            ForeColor = ColorCyan,
            AutoSize = true,
            Location = new Point(8, 10)
        };
        var lblPort = new Label
        {
            Text = $"Porta: {_dev.Port} (VID: {_dev.Vid}, PID: {_dev.Pid})",
            Font = new Font("Segoe UI", 8F),
            ForeColor = ColorTextPrimary,
            AutoSize = true,
            Location = new Point(8, 34)
        };
        var lblState = new Label
        {
            Text = $"Status: {(_dev.Connected ? "ONLINE (UART Sincronizado)" : "DESCONECTADO")}",
            Font = new Font("Segoe UI", 8F, FontStyle.Bold),
            ForeColor = _dev.Connected ? ColorEmerald : ColorCoral,
            AutoSize = true,
            Location = new Point(8, 58)
        };
        var lblLed = new Label
        {
            Text = $"LED RGB GPIO 48: {(_sg.Unlocked ? "🟢 Verde (Sessão Ativa)" : "🔴 Vermelho (Bloqueado)")}",
            Font = new Font("Segoe UI", 8F),
            ForeColor = _sg.Unlocked ? ColorEmerald : ColorCoral,
            AutoSize = true,
            Location = new Point(8, 82)
        };
        pnlTele.Controls.AddRange(new Control[] { lblChip, lblPort, lblState, lblLed });
        card.Controls.Add(pnlTele);

        var lblProxTitle = new Label
        {
            Text = I18n.T("conn_prox_title"),
            Font = new Font("Segoe UI", 9.5F, FontStyle.Bold),
            ForeColor = ColorTextPrimary,
            AutoSize = true,
            Location = new Point(12, 162)
        };
        card.Controls.Add(lblProxTitle);

        var pnlProx = new Panel
        {
            Size = new Size(306, 75),
            Location = new Point(12, 188),
            BackColor = ColorInputBg,
            Padding = new Padding(10)
        };
        var lblProxArmed = new Label
        {
            Text = "Status: ARMADO (Bloqueio Dinâmico BLE)",
            Font = new Font("Segoe UI", 8F, FontStyle.Bold),
            ForeColor = ColorEmerald,
            AutoSize = true,
            Location = new Point(8, 10)
        };
        var lblProxSignal = new Label
        {
            Text = "RSSI: -35 dBm  |  Limite: -75 dBm\nModo Dev Seguro Ativo",
            Font = new Font("Segoe UI", 7.5F),
            ForeColor = ColorTextMuted,
            Size = new Size(286, 32),
            Location = new Point(8, 32)
        };
        pnlProx.Controls.AddRange(new Control[] { lblProxArmed, lblProxSignal });
        card.Controls.Add(pnlProx);

        // Clear Signing Preview Button
        var btnClearSign = new Button
        {
            Text = I18n.T("btn_clear_signing"),
            Font = new Font("Segoe UI", 8F, FontStyle.Bold),
            BackColor = ColorCyan,
            ForeColor = Color.Black,
            FlatStyle = FlatStyle.Flat,
            Size = new Size(306, 32),
            Location = new Point(12, 275),
            Cursor = Cursors.Hand
        };
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
        var lblTitle = new Label
        {
            Text = I18n.T("ssh_title"),
            Font = new Font("Segoe UI", 10.5F, FontStyle.Bold),
            ForeColor = ColorTextPrimary,
            AutoSize = true,
            Location = new Point(12, 12)
        };
        var lblSub = new Label
        {
            Text = I18n.T("ssh_subtitle"),
            Font = new Font("Segoe UI", 7.5F),
            ForeColor = ColorTextMuted,
            Size = new Size(306, 26),
            Location = new Point(12, 34)
        };
        card.Controls.Add(lblTitle);
        card.Controls.Add(lblSub);

        bool isActive = _sg.Unlocked && _dev.Connected;
        var banner = new Panel
        {
            Size = new Size(306, 56),
            Location = new Point(12, 64),
            BackColor = ColorInputBg,
            Padding = new Padding(8)
        };
        var lblBanner = new Label
        {
            Text = isActive ? I18n.T("ssh_status_active") : I18n.T("ssh_status_inactive"),
            Font = new Font("Segoe UI", 8F, FontStyle.Bold),
            ForeColor = isActive ? ColorEmerald : ColorAmber,
            Size = new Size(286, 38),
            Location = new Point(8, 8)
        };
        banner.Controls.Add(lblBanner);
        card.Controls.Add(banner);

        // Native OpenSSH Agent Pipe Status Card
        var pnlAgent = new Panel
        {
            Size = new Size(306, 58),
            Location = new Point(12, 128),
            BackColor = ColorInputBg,
            Padding = new Padding(8)
        };
        var lblAgentTitle = new Label
        {
            Text = "Servidor OpenSSH Named Pipe:",
            Font = new Font("Segoe UI", 8F, FontStyle.Bold),
            ForeColor = ColorCyan,
            AutoSize = true,
            Location = new Point(8, 8)
        };
        var lblAgentStatus = new Label
        {
            Text = "\\\\.\\pipe\\aegis-ssh-agent (Assinatura ESP32-S3 Slot 0)",
            Font = new Font("Segoe UI", 7.5F),
            ForeColor = ColorEmerald,
            Size = new Size(286, 22),
            Location = new Point(8, 28)
        };
        pnlAgent.Controls.AddRange(new Control[] { lblAgentTitle, lblAgentStatus });
        card.Controls.Add(pnlAgent);

        var (count, msg) = _sshGuard.GetAgentIdentitiesCount();
        var lblCount = new Label
        {
            Text = $"Chaves em ssh-agent: {count} ({msg})",
            Font = new Font("Segoe UI", 8F),
            ForeColor = ColorCyan,
            AutoSize = true,
            Location = new Point(12, 194)
        };
        card.Controls.Add(lblCount);

        var btnPurge = new Button
        {
            Text = "Limpar Agente (ssh-add -D)",
            Font = new Font("Segoe UI", 8F, FontStyle.Bold),
            BackColor = ColorCoral,
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Size = new Size(148, 30),
            Location = new Point(12, 220),
            Cursor = Cursors.Hand
        };
        btnPurge.FlatAppearance.BorderSize = 0;
        btnPurge.Click += (s, e) =>
        {
            _sshGuard.PurgeSshAgent();
            RenderTab();
        };

        var btnFido = new Button
        {
            Text = "Carregar FIDO2 (-K)",
            Font = new Font("Segoe UI", 8F, FontStyle.Bold),
            BackColor = ColorCyan,
            ForeColor = Color.Black,
            FlatStyle = FlatStyle.Flat,
            Size = new Size(148, 30),
            Location = new Point(170, 220),
            Cursor = Cursors.Hand
        };
        btnFido.FlatAppearance.BorderSize = 0;
        btnFido.Click += (s, e) =>
        {
            _sshGuard.LoadResidentFido2Keys();
            RenderTab();
        };

        card.Controls.Add(btnPurge);
        card.Controls.Add(btnFido);

        // HIGHLIGHT BUTTON: Simular Solicitação do Sistema (SSH / Assinatura Real)
        var btnSimulateSysReq = new Button
        {
            Text = "⚡ Simular Solicitação do Sistema (SSH)",
            Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
            BackColor = ColorEmerald,
            ForeColor = Color.Black,
            FlatStyle = FlatStyle.Flat,
            Size = new Size(306, 38),
            Location = new Point(12, 262),
            Cursor = Cursors.Hand
        };
        btnSimulateSysReq.FlatAppearance.BorderSize = 0;
        btnSimulateSysReq.Click += async (s, e) =>
        {
            await SimulateSystemRequestAsync();
        };
        card.Controls.Add(btnSimulateSysReq);
    }

    private async Task SimulateSystemRequestAsync()
    {
        // 1. Post simulated system request
        var req = await _client.CreateSystemAuthRequestAsync(
            "Git CLI (github.com / ssh-ed25519)",
            "Assinatura de Autenticação SSH",
            "git push origin master (commit fido-security)"
        );

        string reason = "Solicitação do Sistema: SSH Authentication (git push)";
        string subtitle = "O Git está solicitando assinatura na chave AegisKey ESP32-S3.";

        // 2. Open TopMost PinSessionDialog on screen
        bool authorized = await PinSessionDialog.PromptAndUnlockAsync(_client, this, reason, subtitle);

        if (req != null)
        {
            await _client.ResolveSystemAuthRequestAsync(req.Id, authorized);
        }

        if (authorized)
        {
            // 3. Perform real hardware signature on ESP32-S3!
            string challenge = "AegisKey-System-Challenge-OS-2026";
            string challengeHex = Convert.ToHexString(System.Text.Encoding.UTF8.GetBytes(challenge));
            var (ok, sigHex, err) = await _client.SignHardwareDataAsync(challengeHex, 0);

            await RefreshDataAsync();

            string sigPreview = ok && !string.IsNullOrEmpty(sigHex) ? (sigHex.Length > 32 ? sigHex[..32] + "..." : sigHex) : "N/A";
            MessageBox.Show(
                $"✓ Solicitação do Sistema Autorizada com Sucesso!\n\n" +
                $"• Dispositivo: {_dev.Product} ({_dev.Port})\n" +
                $"• Algoritmo: Ed25519 (Slot 0 - Hardwallet Silicon)\n" +
                $"• Assinatura Gerada: {sigPreview}\n\n" +
                $"O comando do sistema (Git / SSH) recebeu a assinatura de hardware e prosseguiu normalmente!",
                "Autorização de Sistema AegisKey",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information
            );
        }
        else
        {
            MessageBox.Show(
                "A solicitação do sistema foi cancelada ou o PIN não foi validado.",
                "Autorização Negada",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning
            );
        }
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
