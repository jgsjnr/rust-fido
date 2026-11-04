package dev.aegiskey.app

import dev.aegiskey.app.benchmode.BenchSession
import dev.aegiskey.app.domain.model.ConnectionTransportType
import dev.aegiskey.app.domain.model.SecureGuardPolicy
import dev.aegiskey.app.domain.model.SecureGuardStateEnum
import dev.aegiskey.app.domain.model.SecureGuardStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Bench/test session badge (app-android only, read-only).
 *
 * Covers the benchmode decision: badge visible only when firmware/bridge
 * authority proves a bench session (test-mode policy, simulated wipe, or the
 * new `bench_active` contract from the Core `0x3A` status, or the SIMULATOR
 * virtual-bench carrier). Production statuses stay hidden, and the decision
 * is pure (no lock/unlock/wipe effect, no state mutation — production lock
 * flow untouched).
 */
class BenchSessionBadgeTest {

    private fun status(
        testMode: Boolean = false,
        lastWipeSimulated: Boolean = false,
        benchActive: Boolean = false,
        state: SecureGuardStateEnum = SecureGuardStateEnum.LOCKED,
    ) = SecureGuardStatus(
        state = state,
        isProvisioned = state != SecureGuardStateEnum.UNPROVISIONED,
        isUnlocked = state == SecureGuardStateEnum.UNLOCKED,
        policy = SecureGuardPolicy(testModeNonDestructiveWipe = testMode),
        lastWipeSimulated = lastWipeSimulated,
        benchActive = benchActive,
    )

    @Test
    fun firmwareTestMode_marksBench_inEveryState() {
        for (state in SecureGuardStateEnum.entries) {
            assertTrue(
                "test-mode policy must mark bench in $state",
                BenchSession.isBench(status(testMode = true, state = state)),
            )
        }
    }

    @Test
    fun lastWipeSimulated_marksBench() {
        assertTrue(BenchSession.isBench(status(lastWipeSimulated = true)))
        assertTrue(
            BenchSession.isBench(
                status(lastWipeSimulated = true, state = SecureGuardStateEnum.UNLOCKED),
            ),
        )
    }

    @Test
    fun simulatorCarrier_marksBench_evenWithProductionFlags() {
        val production = status()
        assertFalse(BenchSession.isBench(production))
        assertTrue(
            "SIMULATOR virtual-bench carrier (TCP bridge/memory) must mark bench",
            BenchSession.isBench(production, ConnectionTransportType.SIMULATOR),
        )
    }

    @Test
    fun productionTransports_doNotMarkBench() {
        val production = status()
        assertFalse(BenchSession.isBench(production, ConnectionTransportType.BLE))
        assertFalse(BenchSession.isBench(production, ConnectionTransportType.USB))
        assertFalse(BenchSession.isBench(production, ConnectionTransportType.WIFI))
        assertFalse(BenchSession.isBench(production, null))
    }

    @Test
    fun defaultStatus_isNotBench() {
        // Fail-closed default must never show the bench badge in production.
        assertFalse(BenchSession.isBench(SecureGuardStatus()))
    }

    @Test
    fun benchActive_marksBench_inEveryState() {
        // Contrato novo 0x3A `bench_active: bool` — puro read-only.
        for (state in SecureGuardStateEnum.entries) {
            assertTrue(
                "bench_active deve marcar bancada em $state",
                BenchSession.isBench(status(benchActive = true, state = state)),
            )
        }
    }

    @Test
    fun benchActive_absent_defaultsFalse_productionStaysHidden() {
        // Ausente = false: default continua fail-closed.
        assertFalse(BenchSession.isBench(SecureGuardStatus()))
        assertFalse(BenchSession.isBench(status(benchActive = false)))
        assertFalse(
            BenchSession.isBench(status(benchActive = false), ConnectionTransportType.USB),
        )
    }

    @Test
    fun benchActive_cbor_absentDefaultsFalse_presentTranslates() {
        // Tradução estruturada do Core via SecureGuardCbor: nunca inventada.
        val without = dev.aegiskey.app.data.cbor.SecureGuardCbor.encodeMap(
            mapOf("state" to 2, "state_name" to "Locked", "provisioned" to true, "unlocked" to false),
        )
        assertFalse(dev.aegiskey.app.data.cbor.SecureGuardCbor.parseStatus(without)!!.benchActive)

        val withTrue = dev.aegiskey.app.data.cbor.SecureGuardCbor.encodeMap(
            mapOf(
                "state" to 4, "state_name" to "Unlocked",
                "provisioned" to true, "unlocked" to true, "bench_active" to true,
            ),
        )
        val parsedTrue = dev.aegiskey.app.data.cbor.SecureGuardCbor.parseStatus(withTrue)!!
        assertTrue(parsedTrue.benchActive)
        assertTrue(BenchSession.isBench(parsedTrue))

        val withFalse = dev.aegiskey.app.data.cbor.SecureGuardCbor.encodeMap(
            mapOf(
                "state" to 2, "state_name" to "Locked",
                "provisioned" to true, "unlocked" to false, "bench_active" to false,
            ),
        )
        val parsedFalse = dev.aegiskey.app.data.cbor.SecureGuardCbor.parseStatus(withFalse)!!
        assertFalse(parsedFalse.benchActive)
        assertFalse(BenchSession.isBench(parsedFalse))
    }

    @Test
    fun decisionIsPure_doesNotMutateStatusOrLockFlow() {
        val bench = status(testMode = true, state = SecureGuardStateEnum.UNLOCKED)
        val before = bench.copy()
        assertTrue(BenchSession.isBench(bench))
        assertTrue(BenchSession.isBench(bench, ConnectionTransportType.SIMULATOR))
        // No mutation, no lock effect: state/unlock/timers untouched.
        assertEquals(before, bench)
        assertEquals(SecureGuardStateEnum.UNLOCKED, bench.state)
        assertTrue(bench.isUnlocked)

        val contractBench = status(benchActive = true, state = SecureGuardStateEnum.LOCKED)
        val contractBefore = contractBench.copy()
        assertTrue(BenchSession.isBench(contractBench))
        assertEquals(contractBefore, contractBench)
        assertEquals(SecureGuardStateEnum.LOCKED, contractBench.state)

        val production = status(state = SecureGuardStateEnum.UNLOCKED)
        assertFalse(BenchSession.isBench(production, ConnectionTransportType.BLE))
        assertEquals(SecureGuardStateEnum.UNLOCKED, production.state)
        assertTrue(production.isUnlocked)
    }
}
