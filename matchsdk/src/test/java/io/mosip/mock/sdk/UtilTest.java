/*
 * Copyright (c) Modular Open Source Identity Platform
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */
package io.mosip.mock.sdk;

import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

import io.mosip.mock.sdk.util.Util;

public class UtilTest {

    @Test
    public void computeFingerPrint_dataWithoutMetadata_returnsSha256HexString() throws NoSuchAlgorithmException {
        byte[] data = "test_data".getBytes(StandardCharsets.UTF_8);

        String result = Util.computeFingerPrint(data, null);

        Assert.assertNotNull(result);
        Assert.assertEquals(64, result.length());
    }

    @Test
    public void computeFingerPrint_sameDataWithMetadata_returnsDifferentHash() throws NoSuchAlgorithmException {
        byte[] data = "test_data".getBytes(StandardCharsets.UTF_8);

        String hashNoMeta = Util.computeFingerPrint(data, null);
        String hashWithMeta = Util.computeFingerPrint(data, "meta");

        Assert.assertNotEquals(hashNoMeta, hashWithMeta);
    }

    @Test
    public void compareHash_identicalByteArrays_returnsTrue() throws NoSuchAlgorithmException {
        byte[] data = "biometric_sample".getBytes(StandardCharsets.UTF_8);

        Assert.assertTrue(Util.compareHash(data, data));
    }

    @Test
    public void compareHash_differentByteArrays_returnsFalse() throws NoSuchAlgorithmException {
        byte[] data1 = "sample_one".getBytes(StandardCharsets.UTF_8);
        byte[] data2 = "sample_two".getBytes(StandardCharsets.UTF_8);

        Assert.assertFalse(Util.compareHash(data1, data2));
    }

    @Test
    public void encodeToURLSafeBase64_nullByteArray_returnsNull() {
        Assert.assertNull(Util.encodeToURLSafeBase64((byte[]) null));
    }

    @Test
    public void encodeToURLSafeBase64_emptyByteArray_returnsNull() {
        Assert.assertNull(Util.encodeToURLSafeBase64(new byte[0]));
    }

    @Test
    public void encodeToURLSafeBase64_validByteArray_returnsUrlSafeString() {
        byte[] data = "hello world".getBytes(StandardCharsets.UTF_8);

        String encoded = Util.encodeToURLSafeBase64(data);

        Assert.assertNotNull(encoded);
        Assert.assertFalse(encoded.isEmpty());
        Assert.assertFalse(encoded.contains("+"));
        Assert.assertFalse(encoded.contains("/"));
        Assert.assertFalse(encoded.contains("="));
    }

    @Test
    public void encodeToURLSafeBase64_nullString_returnsNull() {
        Assert.assertNull(Util.encodeToURLSafeBase64((String) null));
    }

    @Test
    public void encodeToURLSafeBase64_emptyString_returnsNull() {
        Assert.assertNull(Util.encodeToURLSafeBase64(""));
    }

    @Test
    public void encodeToURLSafeBase64_validString_returnsEncodedString() {
        String encoded = Util.encodeToURLSafeBase64("biometric");

        Assert.assertNotNull(encoded);
        Assert.assertFalse(encoded.isEmpty());
    }

    @Test
    public void decodeURLSafeBase64_nullString_returnsNull() {
        Assert.assertNull(Util.decodeURLSafeBase64(null));
    }

    @Test
    public void decodeURLSafeBase64_emptyString_returnsNull() {
        Assert.assertNull(Util.decodeURLSafeBase64(""));
    }

    @Test
    public void decodeURLSafeBase64_encodedString_returnsOriginalBytes() {
        byte[] original = "hello world".getBytes(StandardCharsets.UTF_8);
        String encoded = Util.encodeToURLSafeBase64(original);

        byte[] decoded = Util.decodeURLSafeBase64(encoded);

        Assert.assertArrayEquals(original, decoded);
    }

    @Test
    public void isNullEmpty_nullByteArray_returnsTrue() {
        Assert.assertTrue(Util.isNullEmpty((byte[]) null));
    }

    @Test
    public void isNullEmpty_emptyByteArray_returnsTrue() {
        Assert.assertTrue(Util.isNullEmpty(new byte[0]));
    }

    @Test
    public void isNullEmpty_nonEmptyByteArray_returnsFalse() {
        Assert.assertFalse(Util.isNullEmpty("data".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    public void isNullEmpty_nullString_returnsTrue() {
        Assert.assertTrue(Util.isNullEmpty((String) null));
    }

    @Test
    public void isNullEmpty_emptyString_returnsTrue() {
        Assert.assertTrue(Util.isNullEmpty(""));
    }

    @Test
    public void isNullEmpty_blankString_returnsTrue() {
        Assert.assertTrue(Util.isNullEmpty("   "));
    }

    @Test
    public void isNullEmpty_nonEmptyString_returnsFalse() {
        Assert.assertFalse(Util.isNullEmpty("data"));
    }
}
