package dev.aegiskey.app.autofill

import android.app.assist.AssistStructure
import android.content.Context
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import dev.aegiskey.app.di.AppContainer
import dev.aegiskey.app.log.DeviceLog
import dev.aegiskey.app.pm.PmCbor
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

/**
 * Android Autofill Framework entrypoint: offers PM-vault passwords in
 * login fields of other apps.
 *
 * Data path (authority only, never invented):
 * AssistStructure parse ([AutofillParser]) -> package/web-domain rank
 * ([AutofillMatcher]) -> punctual per-entry releases (`0x44`, transient)
 * -> one framework [Dataset] per vault entry (device-attested username
 * as presentation, secret as password value) -> wipe every working copy
 * ([AutofillSecrets], [PmCbor.PmRelease.wipe]).
 *
 * Fail-closed contract (each denial answers `onSuccess(null)` — silent,
 * no error surfacing, no partial datasets):
 * - master switch off ([AutofillPrefs], default off) -> null;
 * - no live Secure Guard session ([AutofillGate]) -> null;
 * - no password-class field in the requesting form -> null;
 * - vault unreachable / gate-denied / empty -> null.
 *
 * Saves are refused (`onSaveRequest` answers success without storing):
 * vault writes happen only in-app under UP/PIN gates. No persistence,
 * no logging of payloads (fixed tokens only via [DeviceLog]).
 */
class AegisAutofillService : AutofillService() {

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback,
    ) {
        if (!AutofillPrefs(this).isEnabled()) {
            callback.onSuccess(null)
            return
        }
        if (!AutofillGate.isSessionUnlocked()) {
            DeviceLog.append(DeviceLog.Category.LOCK, "autofill denied locked-session")
            callback.onSuccess(null)
            return
        }
        val structure = request.fillContexts.lastOrNull()?.structure ?: run {
            callback.onSuccess(null)
            return
        }
        val collected = collectFields(structure)
        if (collected.ids.isEmpty()) {
            callback.onSuccess(null)
            return
        }
        val form = AutofillParser.parse(collected.inputs) ?: run {
            callback.onSuccess(null)
            return
        }
        val job = Job()
        cancellationSignal.setOnCancelListener { job.cancel() }
        CoroutineScope(job + Dispatchers.IO).launch {
            try {
                callback.onSuccess(buildResponse(collected, form))
            } catch (_: Throwable) {
                try {
                    callback.onSuccess(null)
                } catch (_: Throwable) {
                }
            }
        }
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        // Vault writes happen only in-app under UP/PIN gates. Refuse here.
        callback.onSuccess()
    }

    private data class Collected(
        val inputs: List<AutofillParser.InputField>,
        val ids: Map<Int, AutofillId>,
        val packageName: String,
        val webDomain: String?,
    )

    private fun collectFields(structure: AssistStructure): Collected {
        val inputs = mutableListOf<AutofillParser.InputField>()
        val ids = mutableMapOf<Int, AutofillId>()
        var webDomain: String? = null
        val packageName = structure.activityComponent?.packageName ?: ""
        for (i in 0 until structure.windowNodeCount) {
            collectNode(structure.getWindowNodeAt(i).rootViewNode, inputs, ids) { domain ->
                if (webDomain == null) webDomain = domain
            }
        }
        return Collected(inputs, ids, packageName, webDomain)
    }

    private fun collectNode(
        node: AssistStructure.ViewNode?,
        inputs: MutableList<AutofillParser.InputField>,
        ids: MutableMap<Int, AutofillId>,
        onWebDomain: (String) -> Unit,
    ) {
        if (node == null) return
        runCatching { node.webDomain }.getOrNull()?.takeIf { it.isNotBlank() }?.let(onWebDomain)
        val autofillId = node.autofillId
        val hints = (node.autofillHints ?: emptyArray()).toSet()
        if (autofillId != null && node.autofillType == android.view.View.AUTOFILL_TYPE_TEXT) {
            val index = inputs.size
            inputs.add(
                AutofillParser.InputField(
                    index = index,
                    hints = hints,
                    inputType = node.inputType,
                    hint = node.hint,
                    focused = node.isFocused,
                ),
            )
            ids[index] = autofillId
        }
        for (i in 0 until node.childCount) {
            collectNode(node.getChildAt(i), inputs, ids, onWebDomain)
        }
    }

    private suspend fun buildResponse(collected: Collected, form: AutofillParser.ParsedForm): FillResponse? {
        val container = runCatching { AppContainer.getInstance(this) }.getOrNull()
            ?: return null
        val page = container.passwordManagerRepository
            .listPage(0L, PmCbor.PM_LIST_DEFAULT_LIMIT)
            .getOrNull() ?: return null
        if (page.page.ids.isEmpty()) return null
        // Bound punctual disclosures per fill: each dataset costs one
        // transient release; the user refines via the in-app viewer.
        val releases = mutableListOf<PmCbor.PmRelease>()
        try {
            for (id in page.page.ids.take(MAX_DATASETS_PER_FILL)) {
                val rel = container.passwordManagerRepository.getRelease(id).getOrNull()
                    ?: continue
                releases.add(rel)
            }
            if (releases.isEmpty()) return null
            val candidates = releases.map { rel ->
                AutofillMatcher.VaultCandidate(
                    id = rel.id,
                    username = rel.username,
                    url = null, // firmware GET discloses {id, username, secret}; never invent url.
                )
            }
            val ranked = AutofillMatcher.rank(candidates, collected.packageName, collected.webDomain)
            // Releases stay paired with their candidate by identity
            // (ByteArray equality is referential, so no cross-wiring).
            val ordered = ranked.mapNotNull { c ->
                releases.firstOrNull { rel -> rel.id === c.id && rel.username == c.username }
            }
            val usernameId = collected.ids[form.usernameIndex]
            val passwordId = collected.ids[form.passwordIndex]
            if (passwordId == null) return null
            val builder = FillResponse.Builder()
            var added = 0
            for (rel in ordered) {
                val dataset = buildDataset(usernameId, passwordId, rel, form.hasUsername)
                    ?: continue
                builder.addDataset(dataset)
                added++
            }
            DeviceLog.append(DeviceLog.Category.SYSTEM, "autofill datasets=$added")
            return if (added > 0) builder.build() else null
        } finally {
            for (rel in releases) runCatching { rel.wipe() }
            releases.clear()
        }
    }

    // RemoteViews presentation is the supported dataset path here (no IME
    // inline flow); the API-34 deprecation targets InlinePresentation
    // migration, which this form does not use.
    @Suppress("DEPRECATION")
    private fun buildDataset(
        usernameId: AutofillId?,
        passwordId: AutofillId,
        rel: PmCbor.PmRelease,
        hasUsername: Boolean,
    ): Dataset? {
        val presentation = RemoteViews(packageName, dev.aegiskey.app.R.layout.autofill_dataset)
        // Authority text only: the device-released username, never a label.
        presentation.setTextViewText(dev.aegiskey.app.R.id.autofill_dataset_text, rel.username)
        val builder = Dataset.Builder()
        if (hasUsername && usernameId != null) {
            builder.setValue(usernameId, AutofillValue.forText(rel.username), presentation)
        }
        val secretChars = rel.secret.decodeToChars()
        try {
            builder.setValue(passwordId, AutofillValue.forText(secretChars.concatToString()), presentation)
        } finally {
            AutofillSecrets.wipe(secretChars)
        }
        return runCatching { builder.build() }.getOrNull()
    }

    private companion object {
        const val MAX_DATASETS_PER_FILL = 8
    }
}

/** UTF-8 decode without retaining an extra String copy beyond the call. */
private fun ByteArray.decodeToChars(): CharArray {
    val text = this.toString(Charsets.UTF_8)
    val chars = CharArray(text.length)
    text.toCharArray(chars)
    return chars
}
