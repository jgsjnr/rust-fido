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
        _sshGuard = new SshAgentGuard(_client, OnPurgeAlert);

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

        _notifyIcon.DoubleClick += (s, e) => ShowMainWindow();

        _sshGuard.StartWatchdog(2);
        ShowMainWindow();
    }

    private void ShowMainWindow()
    {
        _mainWindow.Show();
        _mainWindow.WindowState = FormWindowState.Normal;
        _mainWindow.BringToFront();
        _mainWindow.Activate();
    }

    private void OnPurgeAlert(string message)
    {
        _notifyIcon.ShowBalloonTip(3000, "AegisKey Security Guard", message, ToolTipIcon.Warning);
    }

    protected override void ExitThreadCore()
    {
        _sshGuard.StopWatchdog();
        _notifyIcon.Visible = false;
        _notifyIcon.Dispose();
        base.ExitThreadCore();
    }
}
