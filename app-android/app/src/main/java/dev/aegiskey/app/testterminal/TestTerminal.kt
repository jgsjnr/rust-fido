package dev.aegiskey.app.testterminal

import dev.aegiskey.app.benchmode.BenchSession
import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.domain.model.SecureGuardStatus

/**
 * Terminal de Testes (lab, test-mode only) — single entrypoint do módulo
 * `testterminal`.
 *
 * Catálogo 1:1 com o manifesto do firmware
 * (`crates/aegis-fido-firmware/src/test_hooks.rs`, `TEST_COMMANDS`, 16
 * linhas) e com `docs/test-hooks.md`. Nenhum nome é inventado aqui: linha
 * fora do catálogo nunca é enviada (fail-closed). Sem placa, sem push,
 * sem eFuse/secure-boot: o envio é só texto via `POST /bridge/text_line`
 * (contrato com a lane da ponte); sem o endpoint, a UI mostra
 * "ponte sem suporte".
 *
 * Só traduz autoridade já observada: o gate reaproveita
 * [BenchSession.isBench] (`bench_active` do `0x3A` ou flag test-mode);
 * em release (sem flags) a tela some. Nenhuma telemetria, estado, valor,
 * prosa ou efeito é inventado — acks vindos da ponte são só classificados
 * ([classifyAck]) e exibidos crus no console.
 *
 * Puro (sem Compose/Android): testável em JVM unit.
 */
object TestTerminal {

    /** Caminho do contrato com a lane da ponte. */
    const val BRIDGE_PATH = "/bridge/text_line"

    /** Rótulo fail-closed quando a ponte não tem o endpoint. */
    const val BRIDGE_UNSUPPORTED_LABEL = "ponte sem suporte"

    /**
     * Um comando TEST_* do catálogo: a linha exata enviada à ponte, um
     * título curto, a descrição (de `docs/test-hooks.md`) e o marcador
     * de ack esperado do firmware test-mode.
     */
    data class Hook(
        val line: String,
        val title: String,
        val description: String,
        val expectedAck: String,
    )

    /**
     * Catálogo na ordem do manifesto do firmware (`TEST_COMMANDS`).
     * Fonte de nomes: firmware; aqui só título/descrição/ack esperado.
     */
    val CATALOG: List<Hook> = listOf(
        Hook(
            "TEST_UP",
            "Toque BOOT via software",
            "1 toque BOOT (latch 1x/1,5s). Ack: up_latched source=software.",
            "up_latched source=software",
        ),
        Hook(
            "TEST_DOWNLOAD",
            "Reboot p/ download ROM",
            "Reinicia em modo download ROM via RTC_CNTL (não retorna). Sem botões.",
            "download_mode source=software",
        ),
        Hook(
            "TEST_USB_RECONNECT",
            "Reconecta USB nativo",
            "Drop + re-enumera o USB sem replug físico.",
            "usb_reconnect source=software",
        ),
        Hook(
            "TEST_PAIRING_OPEN",
            "Abre pareamento (60s)",
            "Janela de pareamento de 60s via software (UP/bond seguem).",
            "pairing_open",
        ),
        Hook(
            "TEST_PAIRING_OPEN_300",
            "Abre pareamento (300s)",
            "Janela de 300s p/ testes zero-press.",
            "window_s=300",
        ),
        Hook(
            "TEST_PAIRING_CLOSE",
            "Fecha pareamento",
            "Fecha a janela de teste (vira Locked).",
            "pairing_closed source=software",
        ),
        Hook(
            "TEST_LIFETIME_DUMP",
            "Dump de lifetime",
            "Contadores e estados (ltrace, sem segredos).",
            "lt_dump v=1",
        ),
        Hook(
            "TEST_LED_STATE",
            "Lê estado do LED",
            "Devolve tela + efeito LED atual (somente leitura).",
            "led_state ",
        ),
        Hook(
            "TEST_LED_RED",
            "LED vermelho",
            "Trava o LED em vermelho p/ inspeção visual.",
            "led_set ",
        ),
        Hook(
            "TEST_LED_GREEN",
            "LED verde",
            "Trava o LED em verde p/ inspeção visual.",
            "led_set ",
        ),
        Hook(
            "TEST_LED_BLUE",
            "LED azul",
            "Trava o LED em azul p/ inspeção visual.",
            "led_set ",
        ),
        Hook(
            "TEST_LED_OFF",
            "LED apagado",
            "Apaga o LED p/ inspeção visual.",
            "led_set ",
        ),
        Hook(
            "TEST_LED_RELEASE",
            "Libera LED",
            "Devolve o LED à jornada do produto.",
            "led_set released",
        ),
        Hook(
            "TEST_BENCH_ON",
            "Liga modo bancada",
            "Sessão estendida de 24h em RAM; NVS/eFuse intactos.",
            "bench_on BENCH",
        ),
        Hook(
            "TEST_BENCH_OFF",
            "Desliga modo bancada",
            "Restaura a policy salva; idle padrão volta.",
            "bench_off BENCH",
        ),
        Hook(
            "TEST_OTA_COMMIT_HOOK",
            "Arma hook OTA",
            "Arma hook 1x p/ COMMIT OTA sem BOOT (BEGIN/CHUNK/FINISH inalterados).",
            "ota_commit_hook armed",
        ),
    )

    /** Todos os marcadores de ack conhecidos do firmware test-mode. */
    val KNOWN_ACK_MARKERS: List<String> =
        (CATALOG.map { it.expectedAck } + "source=software").distinct()

    /**
     * Guard da tela: só aparece/ativa quando o device reporta test-mode
     * (`bench_active` do `0x3A` ou flag test-mode), via [BenchSession].
     * Em release (sem flags) retorna false — a tela some.
     */
    fun isVisible(
        status: SecureGuardStatus,
        transport: ConnectionTransportType? = null,
    ): Boolean = BenchSession.isBench(status, transport)

    /** Resultado da classificação de um ack cru da ponte. */
    sealed interface Ack {
        /** Firmware test-mode respondeu com um marcador conhecido. */
        data class Ok(val body: String) : Ack

        /** Corpo vazio: release ignora a linha (sem handler). */
        data object IgnoredRelease : Ack

        /** 2xx com corpo desconhecido: exibe cru, sem interpretar. */
        data object Unrecognized : Ack
    }

    /**
     * Classifica o corpo cru devolvido pela ponte para [line].
     * Nunca inventa conteúdo: só detecta marcadores documentados.
     */
    fun classifyAck(line: String, body: String?): Ack {
        val text = body?.trim().orEmpty()
        if (text.isEmpty()) return Ack.IgnoredRelease
        val hook = CATALOG.find { it.line == line }
        if (hook != null && text.contains(hook.expectedAck)) return Ack.Ok(text)
        if (KNOWN_ACK_MARKERS.any { text.contains(it) }) return Ack.Ok(text)
        return Ack.Unrecognized
    }

    /** Linha de console p/ o envio (`> TEST_*`). */
    fun txLine(line: String): String = "> $line"

    /** Linha de console p/ a resposta crua (`< ack`). */
    fun rxLine(body: String): String = "< ${body.trim()}"

    /** Linha de console fail-closed: ponte sem o endpoint. */
    fun unsupportedLine(): String = "< $BRIDGE_UNSUPPORTED_LABEL"

    /** Linha de console: release ignorou (corpo vazio). */
    fun ignoredLine(): String = "< sem resposta (release ignora a linha)"

    /** Linha de console: falha de transporte até a ponte. */
    fun transportErrorLine(): String = "< erro de transporte (ponte inacessível)"
}
