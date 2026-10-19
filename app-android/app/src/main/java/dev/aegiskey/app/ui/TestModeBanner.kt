package dev.aegiskey.app.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.aegiskey.app.ble.AegisBleClient
import dev.aegiskey.app.ble.BindingOps
import dev.aegiskey.app.ble.VendorOps
import dev.aegiskey.app.log.DeviceLog
import dev.aegiskey.app.security.BindingKey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Banner "MODO TESTE" (decisao 3): aparece quando o firmware conectado
 * nao exige vinculo de verdade (test-mode com bypass).
 *
 * Como descobre: "Verificar" manda LIST (0x22) vazio. Release sem dono
 * responde NEED_BINDING (0x05, so o release emite); firmware de teste
 * deixa passar (OK) ou pede UP. So UP ("aperte o botao...") nao decide:
 * aperte o botao e verifique de novo (teste da OK, release da 0x05).
 * Nenhum dado pessoal e enviado ou logado (so status/tamanho).
 */
private suspend fun probeResponse(client: AegisBleClient): VendorOps.VendorResponse? {
    val raw = client.sendVendor(VendorOps.OP_KEY_LIST, ByteArray(0))
    return VendorOps.parseResponse(raw)
}

@Composable
fun TestModeBanner(client: AegisBleClient, modifier: Modifier = Modifier) {
    val scope = rememberCoroutineScope()
    var testMode by remember { mutableStateOf<Boolean?>(null) }
    var busy by remember { mutableStateOf(false) }
    var hint by remember { mutableStateOf<String?>(null) }

    fun probe() {
        scope.launch {
            busy = true
            hint = null
            try {
                val resp = withContext(Dispatchers.IO) { probeResponse(client) }
                when {
                    resp == null -> hint = "sem resposta - chegue perto e tente de novo"
                    resp.status == BindingOps.STATUS_NEED_BINDING -> {
                        testMode = false
                        hint = "modo seguro: este firmware exige vinculo de verdade"
                        DeviceLog.append(DeviceLog.Category.PAIRING, "mode probe need-binding")
                    }
                    resp.status == VendorOps.STATUS_OK && !BindingKey.hasKey() -> {
                        testMode = true
                        DeviceLog.append(DeviceLog.Category.PAIRING, "mode probe bypass (test)")
                    }
                    resp.status == VendorOps.STATUS_OK ->
                        hint = "este app ja e dono - o vinculo vale, modo indefinido"
                    resp.status == VendorOps.STATUS_NEED_UP ->
                        hint = "aperte o botao do dispositivo e toque em Verificar de novo"
                    else -> hint = VendorOps.statusLabel(resp.status)
                }
            } catch (e: Exception) {
                hint = (e.message ?: "falha ao verificar").take(64)
            } finally {
                busy = false
            }
        }
    }

    if (testMode == true) {
        Card(
            modifier = modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.tertiaryContainer),
        ) {
            Column(Modifier.padding(12.dp)) {
                FriendlyText(text = "MODO TESTE - criptografia flexivel", maxLines = 1)
                FriendlyText(
                    text = "Este firmware aceita configurar sem vinculo. No release a criptografia e obrigatoria: so o dono configura.",
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 3,
                )
            }
        }
    } else {
        Card(modifier = modifier.fillMaxWidth()) {
            Column(Modifier.padding(12.dp)) {
                FriendlyText(text = "Firmware de teste ou de verdade?", maxLines = 1)
                FriendlyText(
                    text = "Toque em Verificar com o dispositivo por perto. Teste mostra o aviso; release exige vinculo.",
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 3,
                )
                if (busy) CircularProgressIndicator()
                Button(
                    onClick = ::probe,
                    enabled = !busy,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Verificar modo", maxLines = 1, overflow = TextOverflow.Ellipsis) }
                hint?.let { FriendlyText(text = it, maxLines = 2) }
            }
        }
    }
}
