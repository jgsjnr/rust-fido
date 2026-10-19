package dev.aegiskey.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/**
 * Journey mirror (see docs/screen-journey.md + docs/app-journey.md).
 * Shows device states and the 5s-hold guide. Never asserts presence.
 */
private data class JourneyStep(val title: String, val body: String)

private val STEPS = listOf(
    JourneyStep("Boot", "Splash + version. LED rainbow. Lands on Home when init is ok."),
    JourneyStep("Home", "Device active, breathing cyan. Hold the button 5s to arm pairing."),
    JourneyStep("Pairing BLE / AP", "6-digit code on LCD, breathing blue. 60s window, then Locked."),
    JourneyStep("Vault", "Label + TOTP code + 30s bar. Auto-clears in 15s back to Home."),
    JourneyStep("Locked", "Red flash. Hold 5s again to re-arm."),
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun OnboardingScreen(onStart: () -> Unit) {
    Scaffold(topBar = { TopAppBar(title = { Text("AegisKey journey") }) }) { inner ->
        Column(
            Modifier.padding(inner).verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text(
                "This app mirrors the device — menus never decide auth.",
                style = MaterialTheme.typography.titleSmall
            )
            for (step in STEPS) {
                Card {
                    Column(Modifier.padding(12.dp)) {
                        Text(step.title, style = MaterialTheme.typography.titleMedium)
                        Text(step.body, style = MaterialTheme.typography.bodyMedium)
                    }
                }
            }
            Card {
                Column(Modifier.padding(12.dp)) {
                    Text("Hold 5s to pair", style = MaterialTheme.typography.titleMedium)
                    Text(
                        "Press and hold the device button for 5 seconds until the fast blink " +
                            "(arming), then confirm the 6-digit code on the Pair screen. " +
                            "Presence (UP) always comes from the button — never from the app."
                    )
                }
            }
            Text(
                "Keys never leave the device. Only envelopes (AEGN) and TOTP codes travel.",
                style = MaterialTheme.typography.bodySmall
            )
            Button(onClick = onStart) { Text("Scan for AegisKey") }
        }
    }
}
