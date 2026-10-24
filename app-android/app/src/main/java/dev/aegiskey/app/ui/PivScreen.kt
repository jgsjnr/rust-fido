package dev.aegiskey.app.ui

import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.foundation.text.KeyboardOptions
import dev.aegiskey.app.ble.AegisBleClient
import dev.aegiskey.app.ble.BleContract
import dev.aegiskey.app.ble.VendorOps
import dev.aegiskey.app.bridge.AegisBridge
import dev.aegiskey.app.log.DeviceLog
import dev.aegiskey.app.security.SdkGate
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * PIV / smartcard (A4): enroll + guia honesto de slots/VERIFY/RSA.
 *
 * - Enrollment: define o PIN (6-8 digitos) + PUK (8 digitos) no dispositivo
 *   via vendor 0x39 (ordem binding -> UP fisico -> PIN; sem binding o device
 *   responde 0x05, sem UP responde 0x01, e o app mostra isso sem oraculo).
 *   Fio: `sendVendor(0x39, [pin_len:1, pin, puk])`; resposta status-first
 *   (`0x00` ok). `0x04` e falha generica OU ja provisionado — o app diz
 *   isso honestamente, sem oraculo.
 * - Gate: toda acao de device (enroll, troca de slot exibido) passa por
 *   `SdkGate.requirePiv()` antes de qualquer fio. Deny/NotCompiled vira
 *   aviso proprio na tela, nunca crash, nunca `todo()`.
 * - Slots: os 4 fixos do firmware — 9A autenticacao (padrao do cartao),
 *   9C assinatura, 9D gerencia de chaves, 9E autenticacao do cartao.
 *   Slot invalido = `6B 00`; PUT sem PIN verificado = `69 82`; cert
 *   ausente = `6A 82`. Este app BLE nao opera slots (sem op de fio):
 *   a lista abaixo e guia estatico p/ OpenSC via USB, sem leitura ao vivo.
 * - RSA honesto: o backend do firmware nao finge RSA — generate/auth com
 *   RSA responde `6A 80` (BadAlg mapeado p/ dado errado). O app nunca
 *   mostra sucesso falso; EC segue via backend do firmware.
 * - Padding FF: o driver PIV real sempre envia o PIN com 8 bytes no fio,
 *   completando com `FF` ([stripDriverPaddingFf] espelha a tolerancia do
 *   firmware). Isso e NORMA DE DRIVER, nao dado do device: o device guarda
 *   so hash+salt+retries, nunca o PIN.
 * - VERIFY (`00 20 00 80`): vazio so consulta (`90 00` ok, `63 CX` faltam X,
 *   `69 83` bloqueado, `6A 88` virgem); PIN certo = `90 00` e zera as 3
 *   tentativas; PIN errado consome 1 (persistido contra queda); zerou =
 *   `63 C0` e dali em diante `69 83` (exige PUK, 3 tentativas; PUK zerou =
 *   wipe total). Tamanho fora de 6-8 = `67 00` sem consumir. O contador
 *   exato (`63 CX`) so aparece no OpenSC/USB — este BLE mostra o teto (3).
 * - Fora de escopo: INS desconhecido = `6D 00` honesto (vide
 *   [pivOutOfScopeLabel]); sem SELECT = `69 85`.
 * - PIN/PUK nunca entram no Log (so opcode/tamanhos/tokens fixos) e os
 *   buffers sao zerados com wipe apos o envio; campos limpos no sucesso.
 * - Sem alegar conformidade smartcard/NIST: os textos descrevem o firmware
 *   observado, sem suite oficial.
 *
 * Textos PT simples, Material3, mesmo padrao das telas existentes.
 */

/** Refs fixas dos 4 slots PIV do firmware (ordem de exibicao). */
private val PIV_SLOT_REFS = intArrayOf(0x9A, 0x9C, 0x9D, 0x9E)

/** Nome curto PT de cada slot (texto estatico do firmware, sem leitura). */
private fun pivSlotName(ref: Int): String = when (ref) {
    0x9A -> "9A · Autenticacao (padrao)"
    0x9C -> "9C · Assinatura"
    0x9D -> "9D · Gerencia de chaves"
    0x9E -> "9E · Autenticacao do cartao"
    else -> "slot invalido (fora de escopo: 6B 00)"
}

/** Papel de cada slot no roteiro OpenSC (honesto, sem execucao aqui). */
private fun pivSlotRole(ref: Int): String = when (ref) {
    0x9A -> "slot padrao do cartao (SELECT volta o last_slot p/ 9A)"
    0x9C -> "chave de assinatura; PUT/GEN exigem PIN verificado"
    0x9D -> "chave de gerencia; PUT/GEN exigem PIN verificado"
    0x9E -> "chave de autenticacao do cartao; PUT/GEN exigem PIN verificado"
    else -> "sem papel: o firmware responde 6B 00"
}

/**
 * Remove o padding `FF` do driver PIV real (espelha `secret_matches_piv`
 * do firmware: PIN de 8B terminado em `FF` tem os `FF`s finais removidos
 * quando o resto fica em 6..=8; resto identico, sem consumir tentativa).
 *
 * NORMA DE DRIVER, NAO DADO DO DEVICE: o driver completa o PIN p/ 8 bytes
 * no fio APDU; o device guarda so hash+salt+retries. Usado na exibicao
 * (previa do fio) e na verificacao local antes do enroll.
 */
private fun stripDriverPaddingFf(candidate: ByteArray): ByteArray {
    if (candidate.size != 8 || candidate.lastOrNull() != 0xFF.toByte()) return candidate
    var n = candidate.size
    while (n > 0 && candidate[n - 1] == 0xFF.toByte()) n -= 1
    if (n in 6..8 && n != candidate.size) return candidate.copyOfRange(0, n)
    return candidate
}

/**
 * Completa o PIN p/ 8 bytes como o driver PIV real faz no fio APDU
 * (padding `FF`). So p/ previa local; o enroll BLE 0x39 envia cru.
 */
private fun padDriverFf(pin: ByteArray): ByteArray {
    if (pin.size >= 8) return pin.copyOf()
    return pin + ByteArray(8 - pin.size) { 0xFF.toByte() }
}

/** Texto honesto do RSA: o firmware responde BadAlg (`6A 80`), sem fingir. */
private fun pivRsaLabel(): String =
    "RSA nao suportado: o device responde 6A 80 (BadAlg honesto). " +
        "So EC via backend do firmware; o app nunca mostra sucesso falso."

/**
 * Mapeamento honesto fora de escopo (igual ao dispatch do firmware):
 * INS desconhecido = `6D 00`; sem SELECT = `69 85`; P2/slot invalido =
 * `6B 00`. Nunca inventa dado: so repete o status que o device daria.
 */
private fun pivOutOfScopeLabel(what: String): String = when (what) {
    "ins" -> "6D 00 (instrucao nao suportada pelo applet PIV)"
    "select" -> "69 85 (selecione o AID PIV antes: 00 A4 04 00)"
    "slot" -> "6B 00 (slot fora de 9A/9C/9D/9E)"
    "pin" -> "69 82 (PIN nao verificado — faca VERIFY antes)"
    "cert" -> "6A 82 (cert ausente no slot — grave com PUT DATA)"
    "virgem" -> "6A 88 (cartao virgem — faca o enroll 0x39)"
    else -> "6D 00 (fora de escopo do applet PIV)"
}

/**
 * Gate R4 p/ aviso proprio (nunca crash): null = pode operar
 * (Success/RealVerified); resto = texto honesto p/ a tela.
 */
private fun pivGateWarning(outcome: SdkGate.GateOutcome): String? = when (outcome) {
    SdkGate.GateOutcome.Success, SdkGate.GateOutcome.RealVerified -> null
    is SdkGate.GateOutcome.NotCompiled ->
        "PIV nao compilado neste build (NotCompiled honesto) — " +
            "sem acao no device; abaixo so o roteiro, sem leitura ao vivo."
    is SdkGate.GateOutcome.ExternalBlocked ->
        "sem transporte nativo (bloqueado) — conecte o device e tente de novo."
    SdkGate.GateOutcome.PermissionDenied ->
        "device pediu prova (UP/PIN/binding) — siga a ordem binding -> UP -> PIN."
    SdkGate.GateOutcome.Unsupported ->
        "operacao nao suportada aqui — veja o roteiro OpenSC abaixo."
    SdkGate.GateOutcome.Unavailable ->
        "device indisponivel agora — tente de novo."
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PivScreen(client: AegisBleClient, onOpenPairing: () -> Unit = {}) {
    val state by client.state.collectAsState()
    val scope = rememberCoroutineScope()
    var pin by remember { mutableStateOf("") }
    var pinConfirm by remember { mutableStateOf("") }
    var puk by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf("—") }
    var upHidden by remember { mutableStateOf(false) }
    var gateNote by remember { mutableStateOf<String?>(null) }
    var slotIdx by remember { mutableStateOf(0) }

    val needsUp = state.status == BleContract.STATUS_UP_NEEDED
    if (!needsUp) upHidden = false

    fun digitsOnly(s: String): String = s.filter { it.isDigit() }

    /** Gate de cada acao: deny/NotCompiled vira aviso proprio, nunca crash. */
    fun checkGate(): Boolean {
        val warning = pivGateWarning(SdkGate.requirePiv())
        gateNote = warning
        if (warning != null) {
            DeviceLog.append(DeviceLog.Category.BLE, "piv gate denied")
            result = warning
            return false
        }
        return true
    }

    /** Geometria local; null = ok, senao a mensagem para o usuario. */
    fun localError(): String? = when {
        pin.any { !it.isDigit() } || puk.any { !it.isDigit() } -> "só números, sem letras nem espaços"
        pin.length !in 6..8 -> "PIN com 6 a 8 números"
        pin != pinConfirm -> "os dois PINs estão diferentes"
        puk.length != 8 -> "PUK com 8 números"
        else -> null
    }

    fun enroll() {
        if (!checkGate()) return
        val err = localError()
        if (err != null) {
            result = err
            return
        }
        scope.launch {
            busy = true
            result = "enviando… toque no botão do dispositivo"
            var pinBytes = ByteArray(0)
            var pukBytes = ByteArray(0)
            var req = ByteArray(0)
            try {
                pinBytes = pin.toByteArray(Charsets.US_ASCII)
                pukBytes = puk.toByteArray(Charsets.US_ASCII)
                req = VendorOps.pivEnrollRequest(pinBytes, pukBytes)
                // Previa do fio APDU (norma de driver, nao dado do device):
                // o driver real completa o PIN p/ 8B com FF; o strip tem que
                // devolver o original. So checagem local, tudo zerado em seguida.
                val driverView = padDriverFf(pinBytes)
                val strippedView = stripDriverPaddingFf(driverView)
                AegisBridge.wipe(driverView, strippedView)
                if (strippedView.size != pinBytes.size) {
                    result = "formato interno divergiu — tente de novo"
                    return@launch
                }
                val raw = withContext(Dispatchers.IO) {
                    client.sendVendor(VendorOps.OP_PIV_ENROLL, req)
                }
                val resp = VendorOps.parseResponse(raw)
                result = when {
                    resp == null -> "sem resposta — toque no dispositivo e tente de novo"
                    resp.status == VendorOps.STATUS_OK -> {
                        DeviceLog.append(DeviceLog.Category.BLE, "piv enroll ok")
                        pin = ""
                        pinConfirm = ""
                        puk = ""
                        "PIV pronto no dispositivo"
                    }
                    resp.status == VendorOps.STATUS_NEED_UP ->
                        "toque no botão do dispositivo e tente de novo"
                    resp.status == VendorOps.STATUS_NEED_BINDING ->
                        "vincule o dispositivo primeiro (tela de pareamento)"
                    resp.status == VendorOps.STATUS_BAD_ENVELOPE ->
                        "não gravou: falhou ou já provisionado — sem como saber qual"
                    else -> VendorOps.statusLabel(resp.status)
                }
            } catch (e: Exception) {
                result = (e.message ?: "falha ao gravar").take(64)
            } finally {
                AegisBridge.wipe(pinBytes, pukBytes, req)
                busy = false
            }
        }
    }

    fun selectSlot(i: Int) {
        if (!checkGate()) return
        slotIdx = i
        val ref = PIV_SLOT_REFS[i]
        DeviceLog.append(DeviceLog.Category.BLE, "piv slot " + String.format("%02X", ref))
    }

    Scaffold(
        topBar = { TopAppBar(title = { Text("PIV / Smartcard", maxLines = 1, overflow = TextOverflow.Ellipsis) }) },
    ) { inner ->
        AegisScreenColumn(inner = inner) {
            TestModeBanner(client)
            if (busy) CircularProgressIndicator()
            FriendlyText(
                text = "BLE: " + state.connection + " · " + BleContract.statusLabel(state.status),
                maxLines = 2,
            )

            if (needsUp && !upHidden) {
                PressDeviceSheet(
                    statusLabel = BleContract.statusLabel(state.status),
                    onCancel = { scope.launch(Dispatchers.IO) { client.cancel() } },
                    onDismiss = { upHidden = true },
                )
            }

            SectionTitle("Criar PIN do cartão")
            FriendlyText(
                text = "O PIN e o PUK ficam só no dispositivo. O app não guarda nem mostra depois.",
                maxLines = 3,
            )
            OutlinedTextField(
                value = pin,
                onValueChange = { pin = digitsOnly(it).take(8) },
                label = { Text("PIN (6 a 8 números)") },
                supportingText = { Text("Só números. É o que você digita no dia a dia.") },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = pinConfirm,
                onValueChange = { pinConfirm = digitsOnly(it).take(8) },
                label = { Text("Repita o PIN") },
                supportingText = { Text("Tem que ser igual ao de cima.") },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = puk,
                onValueChange = { puk = digitsOnly(it).take(8) },
                label = { Text("PUK (8 números)") },
                supportingText = { Text("Só serve para desbloquear se o PIN travar. Guarde em papel.") },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Button(
                onClick = ::enroll,
                enabled = !busy && pin.isNotEmpty() && pinConfirm.isNotEmpty() && puk.isNotEmpty(),
                modifier = Modifier.fillMaxWidth(),
            ) { Text("GRAVAR NO DISPOSITIVO", maxLines = 1, overflow = TextOverflow.Ellipsis) }
            FriendlyText(text = "Resultado: " + result, maxLines = 3)

            gateNote?.let {
                FriendlyText(text = it, maxLines = 4)
            }

            if (result.startsWith("vincule")) {
                OutlinedButton(onClick = onOpenPairing, modifier = Modifier.fillMaxWidth()) {
                    Text("Abrir pareamento", maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
            }

            FriendlyText(
                text = "Se der erro 0x04, pode ser que o cartão já tenha PIN — o dispositivo não conta o motivo.",
                style = MaterialTheme.typography.bodySmall,
                maxLines = 3,
            )

            SectionTitle("Slots do cartão (roteiro OpenSC)")
            FriendlyText(
                text = "4 slots fixos do firmware; 9A e o padrão. Este BLE não opera slots — abaixo e guia p/ OpenSC via USB, sem leitura ao vivo.",
                maxLines = 4,
            )
            PIV_SLOT_REFS.forEachIndexed { i, ref ->
                val selected = i == slotIdx
                OutlinedButton(
                    onClick = { selectSlot(i) },
                    enabled = !busy,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        (if (selected) "[x] " else "[ ] ") + pivSlotName(ref),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
            FriendlyText(text = pivSlotRole(PIV_SLOT_REFS[slotIdx]), maxLines = 3)
            FriendlyText(
                text = "Slot inválido responde 6B 00. PUT sem PIN verificado: 69 82. Cert ausente: 6A 82.",
                style = MaterialTheme.typography.bodySmall,
                maxLines = 3,
            )

            SectionTitle("Conferir PIN (VERIFY) — tentativas à mostra")
            FriendlyText(
                text = "Teto do firmware: 3 tentativas de PIN (e 3 de PUK). Vazio (00 20 00 80 sem dados) só consulta: 90 00 ok, 63 CX faltam X, 69 83 bloqueado, 6A 88 virgem.",
                maxLines = 5,
            )
            FriendlyText(
                text = "PIN certo: 90 00 e zera as tentativas. PIN errado: consome 1 (persiste contra queda) e mostra 63 C2/C1/C0; zerou = 69 83 e exige PUK. Tamanho fora de 6-8: 67 00 sem consumir.",
                maxLines = 5,
            )
            FriendlyText(
                text = "Driver real no fio APDU: PIN sempre com 8 bytes, completando com FF (norma de driver, não dado do device). Aqui: " + pin.length + " dígitos -> " + (if (pin.length in 6..8) 8 - pin.length else 0) + " FF no fio.",
                style = MaterialTheme.typography.bodySmall,
                maxLines = 3,
            )
            FriendlyText(
                text = "O contador exato (63 CX) só aparece no OpenSC via USB — este BLE mostra o teto, sem fingir leitura ao vivo. PUK zerou = wipe total do PIV.",
                style = MaterialTheme.typography.bodySmall,
                maxLines = 4,
            )

            SectionTitle("RSA: 6A 80 honesto")
            FriendlyText(text = pivRsaLabel(), maxLines = 3)
            FriendlyText(
                text = "Generate/auth EC passam pelo backend do firmware; sem backend = 69 85 fechado. P2 inválido = 6B 00.",
                style = MaterialTheme.typography.bodySmall,
                maxLines = 3,
            )

            SectionTitle("Fora de escopo: 6D 00 honesto")
            FriendlyText(text = "INS desconhecido: " + pivOutOfScopeLabel("ins"), maxLines = 2)
            FriendlyText(text = "Sem SELECT: " + pivOutOfScopeLabel("select"), maxLines = 2)
            FriendlyText(text = "Slot/P2 inválido: " + pivOutOfScopeLabel("slot"), maxLines = 2)

            SectionTitle("Roteiro OpenSC (USB)")
            FriendlyText(
                text = "1) Plugue o USB e selecione o AID PIV (00 A4 04 00). 2) Consulte com VERIFY vazio (00 20 00 80). 3) Autentique com VERIFY + PIN (00 20 00 80 + 6-8 dígitos). 4) Opere o slot (PUT/GEN/AUTH) com PIN verificado.",
                maxLines = 6,
            )
            FriendlyText(
                text = "CHUID/CCC são LAB-ONLY no firmware (sem lab-mocks = 6A 82 honesto). Sem device = ExternalBlocked, nunca sucesso falso.",
                style = MaterialTheme.typography.bodySmall,
                maxLines = 4,
            )
        }
    }
}