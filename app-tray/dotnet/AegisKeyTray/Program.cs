namespace AegisKeyTray;

internal static class Program
{
    [STAThread]
    static int Main(string[] args)
    {
        try
        {
            // Canal 2: Modo --askpass / --system-request
            if (args.Length > 0 && (args[0] == "--askpass" || args[0] == "-a" || args[0] == "--system-request"))
            {
                return RunAskPassMode(args);
            }

            ApplicationConfiguration.Initialize();
            var ctx = new TrayApplicationContext();
            Application.Run(ctx);
            return 0;
        }
        catch (Exception ex)
        {
            try
            {
                File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "crash.log"), $"[MainException] {ex}\n");
            }
            catch { }
            return 1;
        }
    }

    private static int RunAskPassMode(string[] args)
    {
        var client = new HardwareBridgeClient();
        try
        {
            var sg = client.GetSecureGuardStatusAsync().GetAwaiter().GetResult();
            var dev = client.DetectDeviceAsync().GetAwaiter().GetResult();

            // Se a chave já estiver desbloqueada, autoriza imediatamente sem incomodar o usuário
            if (dev.Connected && sg.Unlocked)
            {
                Console.WriteLine();
                return 0;
            }

            // Se bloqueada, abre instantaneamente o popup visual PinSessionDialog TopMost na tela!
            ApplicationConfiguration.Initialize();
            string reason = args.Length > 1 ? string.Join(" ", args.Skip(1)) : "OpenSSH / Git Authentication";
            bool authorized = PinSessionDialog.PromptAndUnlockAsync(
                client,
                null,
                $"Solicitação do Sistema: {reason}",
                "O Git/SSH solicita assinatura na chave física AegisKey (COM7)."
            ).GetAwaiter().GetResult();

            if (authorized)
            {
                Console.WriteLine();
                return 0;
            }
            return 1;
        }
        catch (Exception ex)
        {
            try
            {
                File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "askpass_crash.log"), ex.ToString());
            }
            catch { }
            return 1;
        }
    }
}
