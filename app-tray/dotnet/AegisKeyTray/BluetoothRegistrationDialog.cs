using System.Drawing;
using System.Windows.Forms;

namespace AegisKeyTray;

/// <summary>
/// Diálogo modal desacoplado para descoberta e registro de dispositivos Bluetooth
/// na memória do Secure Guard (SRP - Single Responsibility Principle).
/// </summary>
public class BluetoothRegistrationDialog : Form
{
    private static readonly Color ColorBg = ColorTranslator.FromHtml("#0B0F19");
    private static readonly Color ColorCard = ColorTranslator.FromHtml("#111827");
    private static readonly Color ColorInputBg = ColorTranslator.FromHtml("#1A2234");
    private static readonly Color ColorCyan = ColorTranslator.FromHtml("#00E5FF");
    private static readonly Color ColorEmerald = ColorTranslator.FromHtml("#10B981");
    private static readonly Color ColorTextPrimary = ColorTranslator.FromHtml("#F9FAFB");
    private static readonly Color ColorTextMuted = ColorTranslator.FromHtml("#9CA3AF");

    private readonly ComboBox _cmbDevices;
    private readonly TextBox _txtMac;
    private readonly TextBox _txtName;
    private readonly List<BluetoothDeviceItem> _discovered;

    public string SelectedMac => _txtMac.Text.Trim();
    public string SelectedName => _txtName.Text.Trim();

    public BluetoothRegistrationDialog(List<BluetoothDeviceItem> discovered)
    {
        _discovered = discovered ?? new List<BluetoothDeviceItem>();

        Text = "Registrar Bluetooth em Memória (Proximidade)";
        Size = new Size(390, 280);
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        BackColor = ColorBg;
        ForeColor = ColorTextPrimary;

        var lblPrompt = new Label
        {
            Text = "Dispositivos Bluetooth do Windows detectados (ou insira manualmente):",
            Font = new Font("Segoe UI", 8F),
            ForeColor = ColorTextMuted,
            Location = new Point(16, 12),
            Size = new Size(345, 30)
        };

        _cmbDevices = new ComboBox
        {
            Location = new Point(16, 46),
            Size = new Size(342, 24),
            DropDownStyle = ComboBoxStyle.DropDownList,
            BackColor = ColorInputBg,
            ForeColor = ColorTextPrimary,
            FlatStyle = FlatStyle.Flat
        };

        if (_discovered.Count > 0)
        {
            foreach (var d in _discovered)
            {
                _cmbDevices.Items.Add($"{d.Name} ({d.Mac})");
            }
            _cmbDevices.SelectedIndex = 0;
        }
        else
        {
            _cmbDevices.Items.Add("Galaxy S24 Ultra (3C:84:27:C7:17:7A)");
            _cmbDevices.SelectedIndex = 0;
        }

        var lblMac = new Label
        {
            Text = "MAC Address:",
            Font = new Font("Segoe UI", 7.5F),
            ForeColor = ColorTextMuted,
            Location = new Point(16, 80),
            AutoSize = true
        };
        _txtMac = new TextBox
        {
            Location = new Point(16, 98),
            Size = new Size(165, 22),
            BackColor = ColorInputBg,
            ForeColor = ColorTextPrimary,
            BorderStyle = BorderStyle.FixedSingle
        };

        var lblDevName = new Label
        {
            Text = "Nome Dispositivo:",
            Font = new Font("Segoe UI", 7.5F),
            ForeColor = ColorTextMuted,
            Location = new Point(193, 80),
            AutoSize = true
        };
        _txtName = new TextBox
        {
            Location = new Point(193, 98),
            Size = new Size(165, 22),
            BackColor = ColorInputBg,
            ForeColor = ColorTextPrimary,
            BorderStyle = BorderStyle.FixedSingle
        };

        _cmbDevices.SelectedIndexChanged += (s, e) => UpdateFieldsFromSelection();
        UpdateFieldsFromSelection();

        var btnSave = new Button
        {
            Text = "💾 Gravar na Memória do Secure Guard",
            DialogResult = DialogResult.OK,
            Location = new Point(16, 148),
            Size = new Size(342, 34),
            BackColor = ColorEmerald,
            ForeColor = Color.Black,
            FlatStyle = FlatStyle.Flat,
            Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
            Cursor = Cursors.Hand
        };
        btnSave.FlatAppearance.BorderSize = 0;
        btnSave.Click += (s, e) =>
        {
            if (string.IsNullOrWhiteSpace(_txtMac.Text))
            {
                MessageBox.Show("MAC Address é obrigatório.", "Aviso", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                DialogResult = DialogResult.None;
            }
        };

        Controls.AddRange(new Control[] { lblPrompt, _cmbDevices, lblMac, _txtMac, lblDevName, _txtName, btnSave });
    }

    private void UpdateFieldsFromSelection()
    {
        if (_discovered.Count > 0 && _cmbDevices.SelectedIndex >= 0 && _cmbDevices.SelectedIndex < _discovered.Count)
        {
            _txtMac.Text = _discovered[_cmbDevices.SelectedIndex].Mac;
            _txtName.Text = _discovered[_cmbDevices.SelectedIndex].Name;
        }
        else
        {
            _txtMac.Text = "3C:84:27:C7:17:7A";
            _txtName.Text = "Galaxy S24 Ultra";
        }
    }

    /// <summary>
    /// Helper estático para exibição fluente do diálogo (Clean Code).
    /// </summary>
    public static async Task<bool> PromptAndRegisterAsync(IWin32Window owner, HardwareBridgeClient client, bool enforceWindowsLock)
    {
        var discovered = await client.GetBluetoothDevicesAsync();
        using var dlg = new BluetoothRegistrationDialog(discovered);
        if (dlg.ShowDialog(owner) == DialogResult.OK)
        {
            string mac = dlg.SelectedMac;
            string name = dlg.SelectedName;
            bool ok = await client.RegisterProximityDeviceAsync(mac, name, -75, enforceWindowsLock);
            if (ok)
            {
                MessageBox.Show(
                    $"✓ Dispositivo Bluetooth '{name}' ({mac}) registrado com sucesso na memória!\n\n" +
                    "O Secure Guard agora vigia ativamente este dispositivo. Ao afastar, os cofres serão trancados e o Windows Hello / Dynamic Lock será acionado.",
                    "Bluetooth Proximity Registrado",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information
                );
                return true;
            }
            else
            {
                MessageBox.Show("Falha ao registrar dispositivo na ponte de hardware.", "Erro", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
        return false;
    }
}
