using System.Drawing;
using System.Windows.Forms;

namespace AegisKeyTray;

public class TrayApplicationContext : ApplicationContext
{
    private readonly NotifyIcon _notifyIcon;
    private readonly MainWindow _mainWindow;
    private readonly HardwareBridgeClient _client;
    private readonly SshAgentGuard _sshGuard;

    public TrayApplicationContext()
    {
        _client = new HardwareBridgeClient();
        _sshGuard = new SshAgentGuard(_client, OnSecurityNotification);

        _mainWindow = new MainWindow(_client, _sshGuard);

        var menu = new ContextMenuStrip();
        menu.Items.Add(I18n.T("tray_open"), null, (s, e) => ShowMainWindow());
        menu.Items.Add(I18n.T("tray_lock"), null, async (s, e) =>
        {
            await _client.LockSecureGuardAsync();
            await _mainWindow.RefreshDataAsync();
        });
        menu.Items.Add(I18n.T("tray_purge_ssh"), null, (s, e) => _sshGuard.PurgeSshAgent());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(I18n.T("tray_exit"), null, (s, e) => ExitThread());

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

        // REQUIREMENT: Open full Desktop Companion App window centered and visible on startup!
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
        var icon = iconType switch
        {
            2 => ToolTipIcon.Warning,
            3 => ToolTipIcon.Error,
            _ => ToolTipIcon.Info
        };
        _notifyIcon.ShowBalloonTip(3500, title, message, icon);

        // Also notify the active window to refresh data immediately
        _ = _mainWindow.RefreshDataAsync();
    }

    protected override void ExitThreadCore()
    {
        _sshGuard.StopWatchdog();
        _notifyIcon.Visible = false;
        _notifyIcon.Dispose();
        base.ExitThreadCore();
    }
}
