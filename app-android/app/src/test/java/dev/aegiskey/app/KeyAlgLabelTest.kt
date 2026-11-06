package dev.aegiskey.app

import dev.aegiskey.app.ble.VendorOps
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * LIST 0x22 `alg` real por slot (tag 0x05, COSE i32 BE).
 *
 * Autoridade: só dado do device. Mapeamento curto
 * (-7 ES256, -8 EdDSA, -35 ES384, -36 ES512, -47 ES256K);
 * ausente ou fora da tabela = "desconhecido", nunca ES256 inventado.
 */
class KeyAlgLabelTest {

    private fun algBytes(alg: Int): ByteArray = byteArrayOf(
        ((alg shr 24) and 0xFF).toByte(),
        ((alg shr 16) and 0xFF).toByte(),
        ((alg shr 8) and 0xFF).toByte(),
        (alg and 0xFF).toByte(),
    )

    private fun slotTlv(slot: Int, label: String, alg: Int?): ByteArray {
        var tlv = VendorOps.writeTlv(VendorOps.TAG_SLOT, byteArrayOf(slot.toByte())) +
            VendorOps.writeTlv(VendorOps.TAG_LABEL, label.toByteArray(Charsets.UTF_8))
        if (alg != null) {
            tlv += VendorOps.writeTlv(VendorOps.TAG_ALG_HINT, algBytes(alg))
        }
        return tlv
    }

    @Test
    fun coseAlgLabel_mapsAllFiveRealAlgs() {
        assertEquals("ES256", VendorOps.coseAlgLabel(-7))
        assertEquals("EdDSA", VendorOps.coseAlgLabel(-8))
        assertEquals("ES384", VendorOps.coseAlgLabel(-35))
        assertEquals("ES512", VendorOps.coseAlgLabel(-36))
        assertEquals("ES256K", VendorOps.coseAlgLabel(-47))
    }

    @Test
    fun coseAlgLabel_missingIsDesconhecido_neverInvented() {
        assertEquals("desconhecido", VendorOps.coseAlgLabel(null))
    }

    @Test
    fun coseAlgLabel_unknownValuesAreDesconhecido() {
        assertEquals("desconhecido", VendorOps.coseAlgLabel(0))
        assertEquals("desconhecido", VendorOps.coseAlgLabel(-99))
        assertEquals("desconhecido", VendorOps.coseAlgLabel(7))
    }

    @Test
    fun parseKeyList_attachesRealAlgPerSlot() {
        val tlv = slotTlv(0, "k-es256", -7) +
            slotTlv(1, "k-es384", -35) +
            slotTlv(2, "k-eddsa", -8)
        val entries = VendorOps.parseKeyList(tlv)
        assertEquals(3, entries.size)
        assertEquals(0, entries[0].slot)
        assertEquals("k-es256", entries[0].label)
        assertEquals(-7, entries[0].coseAlg)
        assertEquals(1, entries[1].slot)
        assertEquals(-35, entries[1].coseAlg)
        assertEquals(2, entries[2].slot)
        assertEquals(-8, entries[2].coseAlg)
        assertEquals("ES256", VendorOps.coseAlgLabel(entries[0].coseAlg))
        assertEquals("ES384", VendorOps.coseAlgLabel(entries[1].coseAlg))
        assertEquals("EdDSA", VendorOps.coseAlgLabel(entries[2].coseAlg))
    }

    @Test
    fun parseKeyList_missingAlg_isNull_labelDesconhecido() {
        val tlv = VendorOps.writeTlv(VendorOps.TAG_SLOT, byteArrayOf(3)) +
            VendorOps.writeTlv(VendorOps.TAG_LABEL, "legada".toByteArray(Charsets.UTF_8))
        val entries = VendorOps.parseKeyList(tlv)
        assertEquals(1, entries.size)
        assertNull(entries[0].coseAlg)
        assertEquals("desconhecido", VendorOps.coseAlgLabel(entries[0].coseAlg))
    }

    @Test
    fun parseKeyList_malformedAlgLength_isNull() {
        val tlv = VendorOps.writeTlv(VendorOps.TAG_SLOT, byteArrayOf(4)) +
            VendorOps.writeTlv(VendorOps.TAG_LABEL, "k".toByteArray(Charsets.UTF_8)) +
            VendorOps.writeTlv(VendorOps.TAG_ALG_HINT, byteArrayOf(0xFF.toByte()))
        val entries = VendorOps.parseKeyList(tlv)
        assertEquals(1, entries.size)
        assertNull(entries[0].coseAlg)
        assertEquals("desconhecido", VendorOps.coseAlgLabel(entries[0].coseAlg))
    }

    @Test
    fun parseKeyList_unknownTagsIgnored_oldReaderCompat() {
        // Leitor antigo (só 0x01/0x02) segue parseando mesmo com 0x05 no meio.
        val tlv = slotTlv(0, "a", -7) +
            VendorOps.writeTlv(0x09, byteArrayOf(1, 2, 3)) +
            slotTlv(1, "b", -47)
        val entries = VendorOps.parseKeyList(tlv)
        assertEquals(listOf(0, 1), entries.map { it.slot })
        assertEquals(listOf("a", "b"), entries.map { it.label })
        assertEquals("ES256K", VendorOps.coseAlgLabel(entries[1].coseAlg))
    }

    @Test
    fun parseKeyList_unknownAlgValue_preserved_labelDesconhecido() {
        val entries = VendorOps.parseKeyList(slotTlv(5, "futura", -99))
        assertEquals(1, entries.size)
        assertEquals(-99, entries[0].coseAlg)
        assertEquals("desconhecido", VendorOps.coseAlgLabel(entries[0].coseAlg))
    }
}
