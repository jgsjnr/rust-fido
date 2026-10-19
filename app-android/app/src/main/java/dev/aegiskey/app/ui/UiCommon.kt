package dev.aegiskey.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/**
 * Facilidade: espacamento padrao (8/16), tipografia minima legivel,
 * ellipsis para textos longos, rolagem garantida, padding adaptativo
 * simples (compact < 600dp -> 16dp, medium+ -> 24dp).
 *
 * Regras (licoes priorizadas):
 * - Scaffold innerPadding SEMPRE respeitado (caller passa [inner]).
 * - Nada colado: espacamento 8/16.
 * - Textos longos: [FriendlyText] com ellipsis/maxLines, nunca quebra layout.
 * - Telas rolaveis: [AegisScreenColumn].
 * - Sem Log com PII aqui (so UI).
 */
object AegisSpacing {
    val Tight: Dp = 8.dp
    val Normal: Dp = 16.dp
    val Items: Dp = 12.dp
}

/**
 * Coluna padrao de tela: respeita [inner] do Scaffold, rolavel,
 * espacamento 12dp entre itens, padding adaptativo + 16dp vertical.
 * Sem nova dependencia WindowSizeClass: usa screenWidthDp.
 */
@Composable
fun AegisScreenColumn(
    inner: PaddingValues,
    modifier: Modifier = Modifier,
    content: @Composable ColumnScope.() -> Unit,
) {
    val widthDp = LocalConfiguration.current.screenWidthDp
    val h = if (widthDp >= 600) 24.dp else 16.dp
    Column(
        modifier
            .padding(inner)
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = h, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(AegisSpacing.Items),
        content = content,
    )
}

/**
 * Texto amigavel para usuario nao-tecnico: ellipsis, maxLines, tipografia
 * minima legivel (nunca abaixo de bodySmall para conteudo critico).
 */
@Composable
fun FriendlyText(
    text: String,
    style: TextStyle = MaterialTheme.typography.bodyMedium,
    maxLines: Int = 2,
    modifier: Modifier = Modifier,
) {
    Text(
        text = text,
        style = style,
        maxLines = maxLines,
        overflow = TextOverflow.Ellipsis,
        modifier = modifier,
    )
}

/** Estado vazio amigavel ("Toque no dispositivo para carregar" + refresh). */
@Composable
fun FriendlyEmpty(
    message: String = "Nada aqui ainda. Toque no dispositivo para carregar.",
    modifier: Modifier = Modifier,
) {
    Text(
        text = message,
        style = MaterialTheme.typography.bodyMedium,
        maxLines = 3,
        overflow = TextOverflow.Ellipsis,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = modifier,
    )
}

/** Titulo de secao (tipografia minima legivel, ellipsis). */
@Composable
fun SectionTitle(text: String, modifier: Modifier = Modifier) {
    Text(
        text = text,
        style = MaterialTheme.typography.titleMedium,
        maxLines = 1,
        overflow = TextOverflow.Ellipsis,
        modifier = modifier,
    )
}
