using System.Drawing;
using System.Windows.Forms;

namespace AegisKeyTray;

public class TrayApplicationContext : ApplicationContext
{
    private readonly NotifyIcon _notifyIcon;
    private readonly MainWindow _mainWindow;
    private readonly HardwareBridgeClient _client;
    private readonly SshAgentGuard _sshGuard;
    private readonly OpenSshAgentPipeServer _pipeServer;
    private bool _forceExit = false;

    public TrayApplicationContext() : this(new HardwareBridgeClient())
    {
    }

    private TrayApplicationContext(HardwareBridgeClient client)
        : this(client, new SshAgentGuard(client))
    {
    }

    private TrayApplicationContext(HardwareBridgeClient client, SshAgentGuard sshGuard)
        : this(client, sshGuard, new MainWindow(client, sshGuard))
    {
    }

    private TrayApplicationContext(HardwareBridgeClient client, SshAgentGuard sshGuard, MainWindow mainWindow)
        : base(mainWindow)
    {
        _client = client;
        _sshGuard = sshGuard;
        _mainWindow = mainWindow;

        // Native OpenSSH Agent Pipe Server with Interactive UI PIN Dialog prompt
        _pipeServer = new OpenSshAgentPipeServer(_client, "aegis-ssh-agent", _mainWindow.RequestUnlockFromUiAsync);
        _pipeServer.Start();

        var menu = new ContextMenuStrip();
        menu.Items.Add(I18n.T("tray_open"), null, (s, e) => ShowMainWindow());
        menu.Items.Add(I18n.T("tray_lock"), null, async (s, e) =>
        {
            await _client.LockSecureGuardAsync();
            await _mainWindow.RefreshDataAsync();
        });
        menu.Items.Add(I18n.T("tray_purge_ssh"), null, (s, e) => _sshGuard.PurgeSshAgent());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(I18n.T("tray_exit"), null, (s, e) =>
        {
            _forceExit = true;
            ExitThread();
        });

        _notifyIcon = new NotifyIcon
        {
            Icon = SystemIcons.Shield,
            ContextMenuStrip = menu,
            Text = "AegisKey Authenticator & Secure Guard",
            Visible = true
        };

        // Left-click / double-click opens main window
        _notifyIcon.DoubleClick += (s, e) => ShowMainWindow();
        _notifyIcon.BalloonTipClicked += (s, e) => ShowMainWindow();

        // Start background watchdog
        _sshGuard.StartWatchdog(2);

        // Open compact mobile-style floating manager window centered on screen
        ShowMainWindow();
    }

    private void ShowMainWindow()
    {
        _mainWindow.Show();
        _mainWindow.WindowState = FormWindowState.Normal;
        _mainWindow.BringToFront();
        _mainWindow.Activate();
    }

    private void OnSecurityNotification(string title, string message, int iconType)
    {
        if (_mainWindow.IsDisposed) return;
        if (_mainWindow.InvokeRequired)
        {
            _mainWindow.BeginInvoke(new Action(() => OnSecurityNotification(title, message, iconType)));
            return;
        }

        var icon = iconType switch
        {
            2 => ToolTipIcon.Warning,
            3 => ToolTipIcon.Error,
            _ => ToolTipIcon.Info
        };
        try
        {
            _notifyIcon.ShowBalloonTip(3500, title, message, icon);
        }
        catch { }

        _ = _mainWindow.RefreshDataAsync();
    }

    protected override void OnMainFormClosed(object? sender, EventArgs e)
    {
        if (_forceExit)
        {
            base.OnMainFormClosed(sender, e);
        }
    }

    protected override void ExitThreadCore()
    {
        _pipeServer.Stop();
        _sshGuard.StopWatchdog();
        _notifyIcon.Visible = false;
        _notifyIcon.Dispose();
        base.ExitThreadCore();
    }
}
