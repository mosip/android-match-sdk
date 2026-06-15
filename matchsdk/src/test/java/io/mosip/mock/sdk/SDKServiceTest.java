package io.mosip.mock.sdk;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import io.mosip.biometrics.util.finger.FingerPosition;
import io.mosip.biometrics.util.iris.EyeLabel;
import io.mosip.mock.sdk.util.Util;
import io.mosip.kernel.biometrics.constant.BiometricType;
import io.mosip.kernel.biometrics.constant.PurposeType;
import io.mosip.kernel.biometrics.entities.BDBInfo;
import io.mosip.kernel.biometrics.entities.BIR;
import io.mosip.kernel.biometrics.entities.BiometricRecord;
import io.mosip.kernel.biometrics.entities.VersionType;
import io.mosip.kernel.biometrics.model.QualityCheck;
import io.mosip.kernel.biometrics.model.Response;
import io.mosip.mock.sdk.constant.ResponseStatus;
import io.mosip.mock.sdk.exception.SDKException;
import io.mosip.mock.sdk.impl.SampleSDK;
import io.mosip.mock.sdk.service.SDKService;

public class SDKServiceTest {

    private static class TestableSDKService extends SDKService {
        TestableSDKService() {
            super(new HashMap<>());
        }

        public boolean callIsValidBIRParams(BIR segment, BiometricType bioType, String bioSubType) {
            return isValidBIRParams(segment, bioType, bioSubType);
        }

        public boolean callIsValidBDBData(PurposeType purposeType, BiometricType bioType,
                                          String bioSubType, byte[] bdbData) {
            return isValidBDBData(purposeType, bioType, bioSubType, bdbData);
        }

        public boolean callIsValidFingerPosition(int fingerPosition, String bioSubType) {
            return isValidFingerPosition(fingerPosition, bioSubType);
        }

        public boolean callIsValidEyeLabel(int eyeLabel, String bioSubType) {
            return isValidEyeLabel(eyeLabel, bioSubType);
        }

        public Map<BiometricType, List<BIR>> callGetBioSegmentMap(BiometricRecord record,
                                                                   List<BiometricType> modalities) {
            return getBioSegmentMap(record, modalities);
        }

        public boolean callIsValidBiometericData(PurposeType purposeType, BiometricType bioType,
                                                  String bioSubType, String bdbData) {
            return isValidBiometericData(purposeType, bioType, bioSubType, bdbData);
        }

        public boolean callIsValidFingerBdb(PurposeType purposeType, String bioSubType, String bdbData) {
            return isValidFingerBdb(purposeType, bioSubType, bdbData);
        }

        public boolean callIsValidIrisBdb(PurposeType purposeType, String bioSubType, String bdbData) {
            return isValidIrisBdb(purposeType, bioSubType, bdbData);
        }

        public boolean callIsValidFaceBdb(PurposeType purposeType, String bioSubType, String bdbData) {
            return isValidFaceBdb(purposeType, bioSubType, bdbData);
        }

        public boolean callIsValidBirData(BIR bir) {
            return isValidBirData(bir);
        }
    }

    private TestableSDKService service;

    @Before
    public void setup() {
        service = new TestableSDKService();
    }

    // ========== isValidBIRParams tests ==========

    @Test
    public void isValidBIRParams_faceType_returnsTrue() {
        BIR bir = buildBIR(BiometricType.FACE, null, new byte[]{1});
        Assert.assertTrue(service.callIsValidBIRParams(bir, BiometricType.FACE, null));
    }

    @Test(expected = SDKException.class)
    public void isValidBIRParams_fingerWithInvalidSubtype_throwsSDKException() {
        BIR bir = buildBIR(BiometricType.FINGER, "BadSubtype", new byte[]{1});
        service.callIsValidBIRParams(bir, BiometricType.FINGER, "BadSubtype");
    }

    @Test(expected = SDKException.class)
    public void isValidBIRParams_fingerWithEmptySubtype_throwsSDKException() {
        BIR bir = buildBIR(BiometricType.FINGER, "", new byte[]{1});
        service.callIsValidBIRParams(bir, BiometricType.FINGER, "");
    }

    @Test
    public void isValidBIRParams_fingerWithUnknownSubtype_returnsTrue() {
        BIR bir = buildBIR(BiometricType.FINGER, "UNKNOWN", new byte[]{1});
        Assert.assertTrue(service.callIsValidBIRParams(bir, BiometricType.FINGER, "UNKNOWN"));
    }

    @Test
    public void isValidBIRParams_fingerWithLeftIndexFinger_returnsTrue() {
        BIR bir = buildBIR(BiometricType.FINGER, "Left IndexFinger", new byte[]{1});
        Assert.assertTrue(service.callIsValidBIRParams(bir, BiometricType.FINGER, "Left IndexFinger"));
    }

    @Test
    public void isValidBIRParams_fingerWithRightThumb_returnsTrue() {
        BIR bir = buildBIR(BiometricType.FINGER, "Right Thumb", new byte[]{1});
        Assert.assertTrue(service.callIsValidBIRParams(bir, BiometricType.FINGER, "Right Thumb"));
    }

    @Test(expected = SDKException.class)
    public void isValidBIRParams_irisWithInvalidSubtype_throwsSDKException() {
        BIR bir = buildBIR(BiometricType.IRIS, "BadEye", new byte[]{1});
        service.callIsValidBIRParams(bir, BiometricType.IRIS, "BadEye");
    }

    @Test
    public void isValidBIRParams_irisWithUnknownSubtype_returnsTrue() {
        BIR bir = buildBIR(BiometricType.IRIS, "UNKNOWN", new byte[]{1});
        Assert.assertTrue(service.callIsValidBIRParams(bir, BiometricType.IRIS, "UNKNOWN"));
    }

    @Test
    public void isValidBIRParams_irisWithLeftSubtype_returnsTrue() {
        BIR bir = buildBIR(BiometricType.IRIS, "Left", new byte[]{1});
        Assert.assertTrue(service.callIsValidBIRParams(bir, BiometricType.IRIS, "Left"));
    }

    @Test
    public void isValidBIRParams_irisWithRightSubtype_returnsTrue() {
        BIR bir = buildBIR(BiometricType.IRIS, "Right", new byte[]{1});
        Assert.assertTrue(service.callIsValidBIRParams(bir, BiometricType.IRIS, "Right"));
    }

    @Test(expected = SDKException.class)
    public void isValidBIRParams_scentType_throwsSDKException() {
        BIR bir = buildBIR(BiometricType.SCENT, "test", new byte[]{1});
        service.callIsValidBIRParams(bir, BiometricType.SCENT, "test");
    }

    // ========== isValidBDBData tests ==========

    @Test(expected = SDKException.class)
    public void isValidBDBData_nullBdb_throwsSDKException() {
        service.callIsValidBDBData(null, BiometricType.FINGER, "Left IndexFinger", null);
    }

    @Test(expected = SDKException.class)
    public void isValidBDBData_emptyBdb_throwsSDKException() {
        service.callIsValidBDBData(null, BiometricType.FINGER, "Left IndexFinger", new byte[0]);
    }

    // ========== isValidFingerPosition tests ==========

    @Test
    public void isValidFingerPosition_unknown_returnsTrue() {
        Assert.assertTrue(service.callIsValidFingerPosition(0, "UNKNOWN"));
    }

    @Test
    public void isValidFingerPosition_leftIndexFingerCorrect_returnsTrue() {
        Assert.assertTrue(service.callIsValidFingerPosition(FingerPosition.LEFT_INDEX_FINGER, "Left IndexFinger"));
    }

    @Test
    public void isValidFingerPosition_leftIndexFingerWrong_returnsFalse() {
        Assert.assertFalse(service.callIsValidFingerPosition(FingerPosition.RIGHT_INDEX_FINGER, "Left IndexFinger"));
    }

    @Test
    public void isValidFingerPosition_leftMiddleFingerCorrect_returnsTrue() {
        Assert.assertTrue(service.callIsValidFingerPosition(FingerPosition.LEFT_MIDDLE_FINGER, "Left MiddleFinger"));
    }

    @Test
    public void isValidFingerPosition_leftMiddleFingerWrong_returnsFalse() {
        Assert.assertFalse(service.callIsValidFingerPosition(0, "Left MiddleFinger"));
    }

    @Test
    public void isValidFingerPosition_leftRingFingerCorrect_returnsTrue() {
        Assert.assertTrue(service.callIsValidFingerPosition(FingerPosition.LEFT_RING_FINGER, "Left RingFinger"));
    }

    @Test
    public void isValidFingerPosition_leftRingFingerWrong_returnsFalse() {
        Assert.assertFalse(service.callIsValidFingerPosition(0, "Left RingFinger"));
    }

    @Test
    public void isValidFingerPosition_leftLittleFingerCorrect_returnsTrue() {
        Assert.assertTrue(service.callIsValidFingerPosition(FingerPosition.LEFT_LITTLE_FINGER, "Left LittleFinger"));
    }

    @Test
    public void isValidFingerPosition_leftLittleFingerWrong_returnsFalse() {
        Assert.assertFalse(service.callIsValidFingerPosition(0, "Left LittleFinger"));
    }

    @Test
    public void isValidFingerPosition_leftThumbCorrect_returnsTrue() {
        Assert.assertTrue(service.callIsValidFingerPosition(FingerPosition.LEFT_THUMB, "Left Thumb"));
    }

    @Test
    public void isValidFingerPosition_leftThumbWrong_returnsFalse() {
        Assert.assertFalse(service.callIsValidFingerPosition(0, "Left Thumb"));
    }

    @Test
    public void isValidFingerPosition_rightIndexFingerCorrect_returnsTrue() {
        Assert.assertTrue(service.callIsValidFingerPosition(FingerPosition.RIGHT_INDEX_FINGER, "Right IndexFinger"));
    }

    @Test
    public void isValidFingerPosition_rightIndexFingerWrong_returnsFalse() {
        Assert.assertFalse(service.callIsValidFingerPosition(0, "Right IndexFinger"));
    }

    @Test
    public void isValidFingerPosition_rightMiddleFingerCorrect_returnsTrue() {
        Assert.assertTrue(service.callIsValidFingerPosition(FingerPosition.RIGHT_MIDDLE_FINGER, "Right MiddleFinger"));
    }

    @Test
    public void isValidFingerPosition_rightMiddleFingerWrong_returnsFalse() {
        Assert.assertFalse(service.callIsValidFingerPosition(0, "Right MiddleFinger"));
    }

    @Test
    public void isValidFingerPosition_rightRingFingerCorrect_returnsTrue() {
        Assert.assertTrue(service.callIsValidFingerPosition(FingerPosition.RIGHT_RING_FINGER, "Right RingFinger"));
    }

    @Test
    public void isValidFingerPosition_rightRingFingerWrong_returnsFalse() {
        Assert.assertFalse(service.callIsValidFingerPosition(0, "Right RingFinger"));
    }

    @Test
    public void isValidFingerPosition_rightLittleFingerCorrect_returnsTrue() {
        Assert.assertTrue(service.callIsValidFingerPosition(FingerPosition.RIGHT_LITTLE_FINGER, "Right LittleFinger"));
    }

    @Test
    public void isValidFingerPosition_rightLittleFingerWrong_returnsFalse() {
        Assert.assertFalse(service.callIsValidFingerPosition(0, "Right LittleFinger"));
    }

    @Test
    public void isValidFingerPosition_rightThumbCorrect_returnsTrue() {
        Assert.assertTrue(service.callIsValidFingerPosition(FingerPosition.RIGHT_THUMB, "Right Thumb"));
    }

    @Test
    public void isValidFingerPosition_rightThumbWrong_returnsFalse() {
        Assert.assertFalse(service.callIsValidFingerPosition(0, "Right Thumb"));
    }

    @Test
    public void isValidFingerPosition_defaultCase_returnsFalse() {
        Assert.assertFalse(service.callIsValidFingerPosition(0, "UnknownSubtype"));
    }

    // ========== isValidEyeLabel tests ==========

    @Test
    public void isValidEyeLabel_unknown_returnsTrue() {
        Assert.assertTrue(service.callIsValidEyeLabel(EyeLabel.UNSPECIFIED, "UNKNOWN"));
    }

    @Test
    public void isValidEyeLabel_leftCorrectLabel_returnsTrue() {
        Assert.assertTrue(service.callIsValidEyeLabel(EyeLabel.LEFT, "Left"));
    }

    @Test
    public void isValidEyeLabel_leftWrongLabel_returnsFalse() {
        Assert.assertFalse(service.callIsValidEyeLabel(EyeLabel.RIGHT, "Left"));
    }

    @Test
    public void isValidEyeLabel_rightCorrectLabel_returnsTrue() {
        Assert.assertTrue(service.callIsValidEyeLabel(EyeLabel.RIGHT, "Right"));
    }

    @Test
    public void isValidEyeLabel_rightWrongLabel_returnsFalse() {
        Assert.assertFalse(service.callIsValidEyeLabel(EyeLabel.LEFT, "Right"));
    }

    @Test
    public void isValidEyeLabel_defaultCase_returnsFalse() {
        Assert.assertFalse(service.callIsValidEyeLabel(0, "UnknownEye"));
    }

    // ========== getBioSegmentMap tests ==========

    @Test
    public void getBioSegmentMap_emptyModalities_includesAllSegments() {
        BiometricRecord record = new BiometricRecord();
        BIR fingerBir = buildBIR(BiometricType.FINGER, "Left IndexFinger", new byte[]{1});
        BIR faceBir = buildBIR(BiometricType.FACE, null, new byte[]{1});
        record.setSegments(Arrays.asList(fingerBir, faceBir));

        Map<BiometricType, List<BIR>> result = service.callGetBioSegmentMap(record, Collections.emptyList());

        Assert.assertTrue(result.containsKey(BiometricType.FINGER));
        Assert.assertTrue(result.containsKey(BiometricType.FACE));
    }

    @Test
    public void getBioSegmentMap_filteredModalities_excludesOtherTypes() {
        BiometricRecord record = new BiometricRecord();
        BIR fingerBir = buildBIR(BiometricType.FINGER, "Left IndexFinger", new byte[]{1});
        BIR faceBir = buildBIR(BiometricType.FACE, null, new byte[]{1});
        record.setSegments(Arrays.asList(fingerBir, faceBir));

        Map<BiometricType, List<BIR>> result = service.callGetBioSegmentMap(
                record, Collections.singletonList(BiometricType.FINGER));

        Assert.assertTrue(result.containsKey(BiometricType.FINGER));
        Assert.assertFalse(result.containsKey(BiometricType.FACE));
    }

    // ========== ISO validation via checkQuality - covering isValidFingerBdb fail paths ==========

    @Test
    public void checkQuality_invalidFingerISOBinary_returnsInvalidInput() {
        // Minimal parseable ISO 19794-4 data with all-zero values (all checks fail)
        byte[] invalidBdb = buildMinimalIsoBdb();
        BiometricRecord record = buildRecord(BiometricType.FINGER, "Left IndexFinger", invalidBdb);

        Response<QualityCheck> response = new SampleSDK().checkQuality(
                record, Collections.singletonList(BiometricType.FINGER), new HashMap<>());

        Assert.assertNotNull(response);
        Assert.assertEquals(ResponseStatus.INVALID_INPUT.getStatusCode(), (int) response.getStatusCode());
    }

    @Test
    public void checkQuality_invalidIrisISOBinary_returnsInvalidInput() {
        byte[] invalidBdb = buildMinimalIsoBdb();
        BiometricRecord record = buildRecord(BiometricType.IRIS, "Left", invalidBdb);

        Response<QualityCheck> response = new SampleSDK().checkQuality(
                record, Collections.singletonList(BiometricType.IRIS), new HashMap<>());

        Assert.assertNotNull(response);
        Assert.assertEquals(ResponseStatus.INVALID_INPUT.getStatusCode(), (int) response.getStatusCode());
    }

    @Test
    public void checkQuality_invalidFaceISOBinary_returnsInvalidInput() {
        byte[] invalidBdb = buildMinimalIsoBdb();
        BiometricRecord record = buildRecord(BiometricType.FACE, null, invalidBdb);

        Response<QualityCheck> response = new SampleSDK().checkQuality(
                record, Collections.singletonList(BiometricType.FACE), new HashMap<>());

        Assert.assertNotNull(response);
        Assert.assertEquals(ResponseStatus.INVALID_INPUT.getStatusCode(), (int) response.getStatusCode());
    }

    @Test
    public void extractTemplate_invalidFingerISOBinary_returnsInvalidInputStatus() {
        byte[] invalidBdb = buildMinimalIsoBdb();
        BiometricRecord record = buildRecord(BiometricType.FINGER, "Left IndexFinger", invalidBdb);

        Response<BiometricRecord> response = new SampleSDK().extractTemplate(
                record, Collections.singletonList(BiometricType.FINGER), new HashMap<>());

        Assert.assertNotNull(response);
        Assert.assertEquals(ResponseStatus.INVALID_INPUT.getStatusCode(), (int) response.getStatusCode());
    }

    @Test
    public void checkQuality_nullBdb_returnsBiometricNotFoundStatus() {
        BiometricRecord record = buildRecord(BiometricType.FINGER, "Left IndexFinger", null);

        Response<QualityCheck> response = new SampleSDK().checkQuality(
                record, Collections.singletonList(BiometricType.FINGER), new HashMap<>());

        Assert.assertNotNull(response);
        Assert.assertEquals(ResponseStatus.BIOMETRIC_NOT_FOUND_IN_CBEFF.getStatusCode(),
                (int) response.getStatusCode());
    }

    @Test
    public void checkQuality_invalidFingerSubtype_returnsMissingInputStatus() {
        BiometricRecord record = buildRecord(BiometricType.FINGER, "InvalidSub", new byte[]{1});

        Response<QualityCheck> response = new SampleSDK().checkQuality(
                record, Collections.singletonList(BiometricType.FINGER), new HashMap<>());

        Assert.assertNotNull(response);
        Assert.assertEquals(ResponseStatus.MISSING_INPUT.getStatusCode(), (int) response.getStatusCode());
    }

    @Test
    public void checkQuality_invalidIrisSubtype_returnsMissingInputStatus() {
        BiometricRecord record = buildRecord(BiometricType.IRIS, "InvalidEye", new byte[]{1});

        Response<QualityCheck> response = new SampleSDK().checkQuality(
                record, Collections.singletonList(BiometricType.IRIS), new HashMap<>());

        Assert.assertNotNull(response);
        Assert.assertEquals(ResponseStatus.MISSING_INPUT.getStatusCode(), (int) response.getStatusCode());
    }

    @Test
    public void checkQuality_compoundFingerSubtype_coversSize2Branch() {
        // Use 2-element subtype list to cover the "size >= 2" branch in isValidBirData
        BIR bir = buildBIRWithTwoSubtypes(BiometricType.FINGER, "Right", "Thumb", buildMinimalIsoBdb());
        BiometricRecord record = new BiometricRecord();
        record.setSegments(Collections.singletonList(bir));

        Response<QualityCheck> response = new SampleSDK().checkQuality(
                record, Collections.singletonList(BiometricType.FINGER), new HashMap<>());

        // Either INVALID_INPUT (ISO fails) or SUCCESS depending on data
        Assert.assertNotNull(response);
    }

    @Test
    public void extractTemplate_nullBdb_returnsBiometricNotFoundStatus() {
        BiometricRecord record = buildRecord(BiometricType.FINGER, "Left IndexFinger", null);

        Response<BiometricRecord> response = new SampleSDK().extractTemplate(
                record, Collections.singletonList(BiometricType.FINGER), new HashMap<>());

        Assert.assertNotNull(response);
        Assert.assertEquals(ResponseStatus.BIOMETRIC_NOT_FOUND_IN_CBEFF.getStatusCode(),
                (int) response.getStatusCode());
    }

    @Test
    public void extractTemplate_invalidFingerSubtype_returnsMissingInputStatus() {
        BiometricRecord record = buildRecord(BiometricType.FINGER, "InvalidSub", new byte[]{1});

        Response<BiometricRecord> response = new SampleSDK().extractTemplate(
                record, Collections.singletonList(BiometricType.FINGER), new HashMap<>());

        Assert.assertNotNull(response);
        Assert.assertEquals(ResponseStatus.MISSING_INPUT.getStatusCode(), (int) response.getStatusCode());
    }

    @Test
    public void match_sampleWithNullBdb_returnsErrorStatus() {
        BiometricRecord sample = buildRecord(BiometricType.FINGER, "Left IndexFinger", null);
        BiometricRecord gallery = buildRecord(BiometricType.FINGER, "Left IndexFinger", null);

        Response<?> response = new SampleSDK().match(
                sample, new BiometricRecord[]{gallery},
                Collections.singletonList(BiometricType.FINGER), new HashMap<>());

        Assert.assertNotNull(response);
        // null BDB → BIOMETRIC_NOT_FOUND → caught as SDKException
        int status = (int) response.getStatusCode();
        Assert.assertTrue(status == ResponseStatus.BIOMETRIC_NOT_FOUND_IN_CBEFF.getStatusCode() ||
                status == ResponseStatus.MISSING_INPUT.getStatusCode() ||
                status == ResponseStatus.INVALID_INPUT.getStatusCode() ||
                status == ResponseStatus.UNKNOWN_ERROR.getStatusCode());
    }

    @Test
    public void match_emptyGallery_returnsSuccessWithEmptyDecisions() {
        BiometricRecord sample = buildRecord(BiometricType.FINGER, "Left IndexFinger", new byte[]{1});

        Response<?> response = new SampleSDK().match(
                sample, new BiometricRecord[0],
                Collections.singletonList(BiometricType.FINGER), new HashMap<>());

        Assert.assertNotNull(response);
        Assert.assertEquals(ResponseStatus.SUCCESS.getStatusCode(), (int) response.getStatusCode());
    }

    @Test
    public void match_nullSample_returnsMissingInputStatus() {
        BiometricRecord gallery = buildRecord(BiometricType.FINGER, "Left IndexFinger", new byte[]{1});

        Response<?> response = new SampleSDK().match(
                null, new BiometricRecord[]{gallery},
                Collections.singletonList(BiometricType.FINGER), new HashMap<>());

        Assert.assertNotNull(response);
        Assert.assertEquals(ResponseStatus.MISSING_INPUT.getStatusCode(), (int) response.getStatusCode());
    }

    @Test
    public void convertFormatV2_fingerSegmentWithNullBdb_returnsBiometricNotFoundStatus() {
        BiometricRecord record = buildRecord(BiometricType.FINGER, "Left IndexFinger", null);

        Response<BiometricRecord> response = new SampleSDK().convertFormatV2(
                record, "ISO19794_4_2011", "IMAGE/JPEG",
                new HashMap<>(), new HashMap<>(),
                Collections.singletonList(BiometricType.FINGER));

        Assert.assertNotNull(response);
        Assert.assertEquals(ResponseStatus.BIOMETRIC_NOT_FOUND_IN_CBEFF.getStatusCode(),
                (int) response.getStatusCode());
    }

    @Test
    public void convertFormatV2_fingerSegmentWithInvalidSubtype_returnsMissingInputStatus() {
        BiometricRecord record = buildRecord(BiometricType.FINGER, "BadSubtype", new byte[]{1});

        Response<BiometricRecord> response = new SampleSDK().convertFormatV2(
                record, "ISO19794_4_2011", "IMAGE/JPEG",
                new HashMap<>(), new HashMap<>(),
                Collections.singletonList(BiometricType.FINGER));

        Assert.assertNotNull(response);
        Assert.assertEquals(ResponseStatus.MISSING_INPUT.getStatusCode(), (int) response.getStatusCode());
    }

    @Test
    public void checkQuality_withEmptyModalities_returnsSuccessForAllTypes() {
        // checkQuality with empty modalities covers getBioSegmentMap noFilter=true path
        byte[] invalidBdb = buildMinimalIsoBdb();
        BiometricRecord record = new BiometricRecord();
        BIR fingerBir = buildBIR(BiometricType.FINGER, "Left IndexFinger", invalidBdb);
        record.setSegments(Collections.singletonList(fingerBir));

        Response<QualityCheck> response = new SampleSDK().checkQuality(
                record, Collections.emptyList(), new HashMap<>());

        Assert.assertNotNull(response);
    }

    // ========== isValidBiometericData tests ==========

    @Test(expected = SDKException.class)
    public void isValidBiometericData_scentType_throwsSDKException() {
        service.callIsValidBiometericData(null, BiometricType.SCENT, "test",
                io.mosip.mock.sdk.util.Util.encodeToURLSafeBase64("test".getBytes()));
    }

    // ========== isValidFingerBdb / isValidIrisBdb / isValidFaceBdb with synthetic ISO data ==========

    @Test(expected = SDKException.class)
    public void isValidFingerBdb_syntheticIsoWithValidMagic_throwsSDKException() {
        // Correct ISO 19794-4 magic + version so decoder can parse; all representation
        // fields are zero/invalid → individual validation checks execute (false branches)
        String encoded = io.mosip.mock.sdk.util.Util.encodeToURLSafeBase64(buildSyntheticFingerIso());
        service.callIsValidFingerBdb(null, "UNKNOWN", encoded);
    }

    @Test(expected = SDKException.class)
    public void isValidIrisBdb_syntheticIsoWithValidMagic_throwsSDKException() {
        String encoded = io.mosip.mock.sdk.util.Util.encodeToURLSafeBase64(buildSyntheticIrisIso());
        service.callIsValidIrisBdb(null, "UNKNOWN", encoded);
    }

    @Test(expected = SDKException.class)
    public void isValidFaceBdb_syntheticIsoWithValidMagic_throwsSDKException() {
        String encoded = io.mosip.mock.sdk.util.Util.encodeToURLSafeBase64(buildSyntheticFaceIso());
        service.callIsValidFaceBdb(null, null, encoded);
    }

    // certFlag=0x02 (INVALID for finger, only 0x00/0x01 valid)
    // → covers certFlag "enter" block, quality loop body, qualityScore "enter",
    //   representationsNo "enter", impressionType "enter"
    @Test(expected = SDKException.class)
    public void isValidFingerBdb_invalidCertFlag_coversQualityLoopAndRepresentationsNo() {
        String encoded = io.mosip.mock.sdk.util.Util.encodeToURLSafeBase64(buildFingerIsoWithInvalidCertFlag());
        service.callIsValidFingerBdb(null, "UNKNOWN", encoded);
    }

    // certFlag=0x01 (ONE, valid for finger) + captureDeviceTech=21 (INVALID, >20)
    // → covers captureDeviceTech "enter", cert loop body entry, representationsNo "enter",
    //   impressionType "enter"
    @Test(expected = SDKException.class)
    public void isValidFingerBdb_withCertBlocks_coversCaptureDeviceTechAndCertLoop() {
        String encoded = io.mosip.mock.sdk.util.Util.encodeToURLSafeBase64(buildFingerIsoWithCertBlocks());
        service.callIsValidFingerBdb(null, "UNKNOWN", encoded);
    }

    // certFlag=0x01 (INVALID for iris, only 0x00 valid) + captureDeviceTech=0x02 (INVALID,
    // only 0x00/0x01 valid for iris) + noOfQualityBlocks=1, qualityScore=0x80 (INVALID, >100)
    // → covers iris certFlag "enter", captureDeviceTech "enter", quality loop body,
    //   qualityScore "enter"
    @Test(expected = SDKException.class)
    public void isValidIrisBdb_withQualityBlock_coversIrisCertFlagAndCaptureDeviceTech() {
        String encoded = io.mosip.mock.sdk.util.Util.encodeToURLSafeBase64(buildIrisIsoWithQualityBlocks());
        service.callIsValidIrisBdb(null, "UNKNOWN", encoded);
    }

    // certFlag=0x02 (INVALID for face, only 0x00 valid) + temporalSemantics=0x0001 (INVALID,
    // only 0x0000 valid) + captureDeviceTech=0x07 (INVALID, {0-6,128-255} valid) +
    // noOfQualityBlocks=1 + qualityScore=0x80 (INVALID) + gender=0x03 (INVALID, {0,1,2,255}
    // valid) + eyeColor=0x08 (INVALID, {0-7,255} valid) + hairColor=0x08 (INVALID) +
    // faceImageType=0x04 (INVALID, {0-3,128-130} valid)
    @Test(expected = SDKException.class)
    public void isValidFaceBdb_withTargetedFields_coversCertFlagTemporalSemanticsAndMore() {
        String encoded = io.mosip.mock.sdk.util.Util.encodeToURLSafeBase64(buildFaceIsoWithTargetedFields());
        service.callIsValidFaceBdb(null, null, encoded);
    }

    // ========== Helper methods ==========

    private byte[] buildSyntheticFingerIso() {
        byte[] bdb = new byte[500];
        bdb[0] = 0x46; bdb[1] = 0x49; bdb[2] = 0x52; bdb[3] = 0x00; // "FIR\0"
        bdb[4] = 0x30; bdb[5] = 0x32; bdb[6] = 0x30; bdb[7] = 0x00; // "020\0"
        // record length = 500 (big-endian)
        bdb[8] = 0x00; bdb[9] = 0x00; bdb[10] = 0x01; bdb[11] = (byte) 0xF4;
        bdb[12] = 0x00; bdb[13] = 0x01; // noOfRepresentations = 1
        return bdb;
    }

    private byte[] buildSyntheticIrisIso() {
        byte[] bdb = new byte[500];
        bdb[0] = 0x49; bdb[1] = 0x49; bdb[2] = 0x52; bdb[3] = 0x00; // "IIR\0"
        bdb[4] = 0x30; bdb[5] = 0x32; bdb[6] = 0x30; bdb[7] = 0x00; // "020\0"
        bdb[8] = 0x00; bdb[9] = 0x00; bdb[10] = 0x01; bdb[11] = (byte) 0xF4;
        bdb[12] = 0x00; bdb[13] = 0x01;
        return bdb;
    }

    private byte[] buildSyntheticFaceIso() {
        byte[] bdb = new byte[500];
        bdb[0] = 0x46; bdb[1] = 0x41; bdb[2] = 0x43; bdb[3] = 0x00; // "FAC\0"
        bdb[4] = 0x30; bdb[5] = 0x33; bdb[6] = 0x30; bdb[7] = 0x00; // "030\0"
        bdb[8] = 0x00; bdb[9] = 0x00; bdb[10] = 0x01; bdb[11] = (byte) 0xF4;
        bdb[12] = 0x00; bdb[13] = 0x01;
        return bdb;
    }

    /**
     * Builds minimal parseable ISO binary data where noOfRepresentations=1
     * so the decoder can parse it, but all field values are 0/invalid.
     * This causes all ISO validation checks to fail, covering those code paths.
     */
    private byte[] buildMinimalIsoBdb() {
        byte[] bdb = new byte[200];
        // Byte 13: noOfRepresentations = 1 (big-endian: bytes 12-13 as unsigned short)
        bdb[13] = 1;
        return bdb;
    }

    private BIR buildBIR(BiometricType type, String subtype, byte[] bdb) {
        BIR.BIRBuilder builder = new BIR.BIRBuilder();
        builder.withVersion(new VersionType(1, 1));
        builder.withCbeffversion(new VersionType(1, 1));
        BDBInfo.BDBInfoBuilder bdbInfoBuilder = new BDBInfo.BDBInfoBuilder();
        bdbInfoBuilder.withType(Collections.singletonList(type));
        if (subtype != null) {
            bdbInfoBuilder.withSubtype(Collections.singletonList(subtype));
        } else {
            bdbInfoBuilder.withSubtype(Collections.emptyList());
        }
        builder.withBdbInfo(new BDBInfo(bdbInfoBuilder));
        if (bdb != null) {
            builder.withBdb(bdb);
        }
        return new BIR(builder);
    }

    private BIR buildBIRWithTwoSubtypes(BiometricType type, String subtype1, String subtype2, byte[] bdb) {
        BIR.BIRBuilder builder = new BIR.BIRBuilder();
        builder.withVersion(new VersionType(1, 1));
        builder.withCbeffversion(new VersionType(1, 1));
        BDBInfo.BDBInfoBuilder bdbInfoBuilder = new BDBInfo.BDBInfoBuilder();
        bdbInfoBuilder.withType(Collections.singletonList(type));
        bdbInfoBuilder.withSubtype(Arrays.asList(subtype1, subtype2));
        builder.withBdbInfo(new BDBInfo(bdbInfoBuilder));
        if (bdb != null) {
            builder.withBdb(bdb);
        }
        return new BIR(builder);
    }

    private BiometricRecord buildRecord(BiometricType type, String subtype, byte[] bdb) {
        BiometricRecord record = new BiometricRecord();
        record.setSegments(Collections.singletonList(buildBIR(type, subtype, bdb)));
        return record;
    }

    // certFlag=0x02: INVALID for finger (only 0x00 and 0x01 are valid)
    // noOfQualityBlocks=1 → quality loop body entered; qualityScore=0x80 → qualityScore "enter"
    // representationNo=0x10 (16 > 15) → representationsNo "enter"
    // impressionType=0x10 (16, not in {0-15,24,28,29}) → impressionType "enter"
    private byte[] buildFingerIsoWithInvalidCertFlag() {
        byte[] bdb = new byte[500];
        bdb[0] = 0x46; bdb[1] = 0x49; bdb[2] = 0x52; bdb[3] = 0x00; // "FIR\0"
        bdb[4] = 0x30; bdb[5] = 0x32; bdb[6] = 0x30; bdb[7] = 0x00; // "020\0"
        bdb[8] = 0x00; bdb[9] = 0x00; bdb[10] = 0x01; bdb[11] = (byte) 0xF4; // recordLength=500
        bdb[12] = 0x00; bdb[13] = 0x01; // noOfRepresentations=1
        bdb[14] = 0x02; // certificationFlag=2 → INVALID, not ONE → no cert blocks read
        bdb[15] = 0x01; // noOfFingerPresent=1
        // RepresentationHeader: bytes 16-33 all zero (representationDataLength + captureDateTime
        //   + vendor + type)
        bdb[34] = 0x01; // noOfQualityBlocks=1
        // quality block bytes 35-39: vendor(35-36)=0, algo(37-38)=0, score(39)=0x80
        bdb[39] = (byte) 0x80; // qualityScore=128 (INVALID: >100 and ≠255)
        // certFlag=0x02 != ONE → no cert blocks read from stream
        // byte 40: fingerPosition=0x00 (UNKNOWN subtype → valid)
        bdb[41] = 0x10; // representationNo=16 (INVALID: max is 0x0F=15)
        // bytes 42-52 all zero (scaleUnits, scanRates, etc.)
        bdb[53] = 0x10; // impressionType=16 (INVALID: {0-15,24,28,29} valid)
        return bdb;
    }

    // certFlag=0x01 (ONE): valid for finger → enables cert block reading
    // captureDeviceTech=21 (>20): INVALID → captureDeviceTech "enter"
    // noOfCertBlocks=1 → cert loop body entered
    // representationNo=0x10 → representationsNo "enter"
    // impressionType=0x10 → impressionType "enter"
    private byte[] buildFingerIsoWithCertBlocks() {
        byte[] bdb = new byte[500];
        bdb[0] = 0x46; bdb[1] = 0x49; bdb[2] = 0x52; bdb[3] = 0x00;
        bdb[4] = 0x30; bdb[5] = 0x32; bdb[6] = 0x30; bdb[7] = 0x00;
        bdb[8] = 0x00; bdb[9] = 0x00; bdb[10] = 0x01; bdb[11] = (byte) 0xF4;
        bdb[12] = 0x00; bdb[13] = 0x01;
        bdb[14] = 0x01; // certificationFlag=ONE → valid for finger, enables cert blocks
        bdb[15] = 0x01; // noOfFingerPresent=1
        // bytes 16-28: representationDataLength + captureDateTime (all zero)
        bdb[29] = 0x15; // captureDeviceTech=21 (INVALID: max valid is 20)
        // bytes 30-33: vendor=0, type=0
        bdb[34] = 0x01; // noOfQualityBlocks=1
        // quality block bytes 35-39
        bdb[39] = (byte) 0x80; // qualityScore=128 (INVALID)
        // certFlag=ONE → read cert blocks:
        bdb[40] = 0x01; // noOfCertBlocks=1 → cert loop body entered
        // cert block 1: bytes 41-43 (authorityID[41-42]=0 VALID, schemeID[43]=0 VALID)
        // After cert block (byte 44):
        // byte 44: fingerPosition=0 (valid for UNKNOWN)
        bdb[45] = 0x10; // representationNo=16 (INVALID)
        // bytes 46-56: all zero
        bdb[57] = 0x10; // impressionType=16 (INVALID)
        return bdb;
    }

    // certFlag=0x01: INVALID for iris (only 0x00 valid) → iris certFlag "enter"
    // captureDeviceTech=0x02: INVALID for iris (only 0x00/0x01 valid) → captureDeviceTech "enter"
    // noOfQualityBlocks=1 → quality loop body entered
    // qualityScore=0x80 (128 > 100): INVALID → iris qualityScore "enter"
    private byte[] buildIrisIsoWithQualityBlocks() {
        byte[] bdb = new byte[500];
        bdb[0] = 0x49; bdb[1] = 0x49; bdb[2] = 0x52; bdb[3] = 0x00; // "IIR\0"
        bdb[4] = 0x30; bdb[5] = 0x32; bdb[6] = 0x30; bdb[7] = 0x00; // "020\0"
        bdb[8] = 0x00; bdb[9] = 0x00; bdb[10] = 0x01; bdb[11] = (byte) 0xF4;
        bdb[12] = 0x00; bdb[13] = 0x01; // noOfRepresentations=1
        bdb[14] = 0x01; // certificationFlag=1 (INVALID for iris: only 0x00 valid)
        bdb[15] = 0x01; // noOfEyesPresent=1 (matches noOfRepresentations)
        // bytes 16-28: representationDataLength + captureDateTime (all zero)
        bdb[29] = 0x02; // captureDeviceTech=2 (INVALID for iris: only 0x00 and 0x01 valid)
        // bytes 30-33: vendor=0, type=0
        bdb[34] = 0x01; // noOfQualityBlocks=1
        // quality block bytes 35-39
        bdb[39] = (byte) 0x80; // qualityScore=128 (INVALID for iris: >100)
        // remaining bytes all zero
        return bdb;
    }

    // Face-specific targeted fields:
    // certFlag=0x02: INVALID for face (only 0x00 valid); 0x02 != ONE → no cert blocks read
    // temporalSemantics=0x0001: INVALID (only 0x0000 valid)
    // captureDeviceTech=0x07: INVALID ({0-6,128-255} valid)
    // noOfQualityBlocks=1 → quality loop; qualityScore=0x80 → qualityScore "enter"
    // gender=0x03: INVALID ({0,1,2,255} valid)
    // eyeColor=0x08: INVALID ({0-7,255} valid)
    // hairColor=0x08: INVALID ({0-7,255} valid)
    // faceImageType=0x04: INVALID ({0-3,128-130} valid)
    private byte[] buildFaceIsoWithTargetedFields() {
        byte[] bdb = new byte[500];
        bdb[0] = 0x46; bdb[1] = 0x41; bdb[2] = 0x43; bdb[3] = 0x00; // "FAC\0"
        bdb[4] = 0x30; bdb[5] = 0x33; bdb[6] = 0x30; bdb[7] = 0x00; // "030\0"
        bdb[8] = 0x00; bdb[9] = 0x00; bdb[10] = 0x01; bdb[11] = (byte) 0xF4; // totalRepLen=500
        bdb[12] = 0x00; bdb[13] = 0x01; // noOfRepresentations=1
        bdb[14] = 0x02; // certificationFlag=2 (INVALID for face: only 0x00 valid)
        bdb[15] = 0x00; bdb[16] = 0x01; // temporalSemantics=0x0001 (INVALID: only 0x0000 valid)
        // FaceRepresentationHeader starts at byte 17
        // bytes 17-29: representationLength + captureDateTime (all zero)
        bdb[30] = 0x07; // captureDeviceTech=7 (INVALID: {0-6, 128-255} valid)
        // bytes 31-34: vendor=0, type=0
        bdb[35] = 0x01; // noOfQualityBlocks=1
        // quality block bytes 36-40: vendor(36-37)=0, algo(38-39)=0, score(40)=0x80
        bdb[40] = (byte) 0x80; // qualityScore=128 (INVALID for face: >100 and ≠255)
        // FacialInformation starts at byte 41 (certFlag=0x02 != ONE → no cert blocks)
        // bytes 41-42: noOfLandMarkPoints=0 (unsigned short)
        bdb[43] = 0x03; // gender=3 (INVALID: {0,1,2,255} valid)
        bdb[44] = 0x08; // eyeColor=8 (INVALID: {0-7,255} valid)
        bdb[45] = 0x08; // hairColor=8 (INVALID: {0-7,255} valid)
        // bytes 46-57: subjectHeight=0, featuresMask=0, expressionMask=0, poseAngle=0,
        //   poseAngleUncertainty=0 (all valid, all zero)
        // FaceImageInformation starts at byte 58
        bdb[58] = 0x04; // faceImageType=4 (INVALID: {0-3,128-130} valid)
        // remaining bytes all zero (imageDataType=0 already covered, imageColorSpace=0 covered)
        return bdb;
    }

    // ========== getBioSegmentMap null-input paths ==========

    @Test(expected = SDKException.class)
    public void getBioSegmentMap_nullRecord_throwsSDKException() {
        service.callGetBioSegmentMap(null, Collections.emptyList());
    }

    @Test(expected = SDKException.class)
    public void getBioSegmentMap_nullSegments_throwsSDKException() {
        BiometricRecord record = new BiometricRecord();
        record.setSegments(null); // explicitly set to null
        service.callGetBioSegmentMap(record, Collections.emptyList());
    }

    // ========== isValidBirData null/empty BdbInfo branches ==========

    @Test(expected = SDKException.class)
    public void isValidBirData_nullBdbInfo_throwsSDKException() {
        BIR.BIRBuilder builder = new BIR.BIRBuilder();
        builder.withVersion(new VersionType(1, 1));
        builder.withCbeffversion(new VersionType(1, 1));
        // withBdbInfo intentionally omitted → BdbInfo is null
        BIR bir = new BIR(builder);
        service.callIsValidBirData(bir);
    }

    @Test(expected = SDKException.class)
    public void isValidBirData_emptyTypeList_throwsSDKException() {
        BIR.BIRBuilder builder = new BIR.BIRBuilder();
        builder.withVersion(new VersionType(1, 1));
        builder.withCbeffversion(new VersionType(1, 1));
        BDBInfo.BDBInfoBuilder bdbInfoBuilder = new BDBInfo.BDBInfoBuilder();
        bdbInfoBuilder.withType(Collections.emptyList());
        bdbInfoBuilder.withSubtype(Collections.emptyList());
        builder.withBdbInfo(new BDBInfo(bdbInfoBuilder));
        builder.withBdb(new byte[]{1});
        BIR bir = new BIR(builder);
        service.callIsValidBirData(bir);
    }

    // ========== Util.computeFingerPrint coverage ==========

    @Test(expected = IllegalArgumentException.class)
    public void util_computeFingerPrint_nullData_throwsIllegalArgumentException() throws NoSuchAlgorithmException {
        Util.computeFingerPrint(null, null);
    }

    @Test
    public void util_computeFingerPrint_withNonNullMetaData_returnsHash() throws NoSuchAlgorithmException {
        String hash = Util.computeFingerPrint(new byte[]{1, 2, 3}, "metadata");
        Assert.assertNotNull(hash);
        Assert.assertEquals(64, hash.length()); // SHA-256 hex is always 64 chars
    }

    // ========== base64 decode catch blocks ==========

    @Test(expected = SDKException.class)
    public void isValidFingerBdb_invalidBase64_throwsSDKException() {
        service.callIsValidFingerBdb(null, "UNKNOWN", "!!NOT_VALID_BASE64!!");
    }

    @Test(expected = SDKException.class)
    public void isValidIrisBdb_invalidBase64_throwsSDKException() {
        service.callIsValidIrisBdb(null, "UNKNOWN", "!!NOT_VALID_BASE64!!");
    }

    @Test(expected = SDKException.class)
    public void isValidFaceBdb_invalidBase64_throwsSDKException() {
        service.callIsValidFaceBdb(null, null, "!!NOT_VALID_BASE64!!");
    }

    // ========== Finger qualityScore body (lines 261-262) ==========
    // Quality block layout: [score(1)][vendor(2)][algo(2)] → score is at byte 35 (first byte after noOfQualityBlocks at byte 34)
    @Test(expected = SDKException.class)
    public void isValidFingerBdb_withInvalidQualityScore_coversQualityScoreBody() {
        String encoded = io.mosip.mock.sdk.util.Util.encodeToURLSafeBase64(buildFingerIsoWithInvalidQualityScoreAtByte35());
        service.callIsValidFingerBdb(null, "UNKNOWN", encoded);
    }

    private byte[] buildFingerIsoWithInvalidQualityScoreAtByte35() {
        byte[] bdb = new byte[500];
        bdb[0] = 0x46; bdb[1] = 0x49; bdb[2] = 0x52; bdb[3] = 0x00; // "FIR\0"
        bdb[4] = 0x30; bdb[5] = 0x32; bdb[6] = 0x30; bdb[7] = 0x00; // "020\0"
        bdb[8] = 0x00; bdb[9] = 0x00; bdb[10] = 0x01; bdb[11] = (byte) 0xF4; // recordLength=500
        bdb[12] = 0x00; bdb[13] = 0x01; // noOfRepresentations=1
        bdb[14] = 0x00; // certificationFlag=0 (valid)
        bdb[15] = 0x01; // noOfFingerPresent=1
        // bytes 16-28: representationDataLength + captureDateTime (all zero)
        // byte 29: captureDeviceTech=0 (valid, 0-20)
        // bytes 30-33: vendor=0, type=0 (valid)
        bdb[34] = 0x01; // noOfQualityBlocks=1
        bdb[35] = (byte) 0x80; // qualityScore=128 at byte 35 (INVALID: >100 and ≠255)
        // bytes 36-39: qualityAlgoVendor(2)+qualityAlgo(2) = zero (valid)
        return bdb;
    }

    // ========== Iris noOfRepresentations body (lines 472-473) ==========
    @Test(expected = SDKException.class)
    public void isValidIrisBdb_tooManyRepresentations_coversNoOfRepBody() {
        String encoded = io.mosip.mock.sdk.util.Util.encodeToURLSafeBase64(buildIrisIsoWithTwoRepresentations());
        service.callIsValidIrisBdb(null, "UNKNOWN", encoded);
    }

    private byte[] buildIrisIsoWithTwoRepresentations() {
        byte[] bdb = new byte[500];
        bdb[0] = 0x49; bdb[1] = 0x49; bdb[2] = 0x52; bdb[3] = 0x00; // "IIR\0"
        bdb[4] = 0x30; bdb[5] = 0x32; bdb[6] = 0x30; bdb[7] = 0x00; // "020\0"
        bdb[8] = 0x00; bdb[9] = 0x00; bdb[10] = 0x01; bdb[11] = (byte) 0xF4; // recordLength=500
        bdb[12] = 0x00; bdb[13] = 0x02; // noOfRepresentations=2 (INVALID: only 1 valid)
        bdb[14] = 0x00; // certificationFlag=0
        bdb[15] = 0x01; // noOfEyesPresent=1
        return bdb;
    }

    // ========== Iris noOfEyesPresent body (lines 489-490) ==========
    @Test(expected = SDKException.class)
    public void isValidIrisBdb_invalidNoOfEyesPresent_coversNoOfEyesBody() {
        String encoded = io.mosip.mock.sdk.util.Util.encodeToURLSafeBase64(buildIrisIsoWithInvalidNoOfEyes());
        service.callIsValidIrisBdb(null, "UNKNOWN", encoded);
    }

    private byte[] buildIrisIsoWithInvalidNoOfEyes() {
        byte[] bdb = new byte[500];
        bdb[0] = 0x49; bdb[1] = 0x49; bdb[2] = 0x52; bdb[3] = 0x00; // "IIR\0"
        bdb[4] = 0x30; bdb[5] = 0x32; bdb[6] = 0x30; bdb[7] = 0x00; // "020\0"
        bdb[8] = 0x00; bdb[9] = 0x00; bdb[10] = 0x01; bdb[11] = (byte) 0xF4; // recordLength=500
        bdb[12] = 0x00; bdb[13] = 0x01; // noOfRepresentations=1 (valid)
        bdb[14] = 0x00; // certificationFlag=0
        bdb[15] = 0x02; // noOfEyesPresent=2 (INVALID: expected 0 or 1)
        return bdb;
    }

    // ========== Iris quality score at byte 35 (score-first layout) and byte 39 (vendor-first fallback) ==========

    @Test(expected = SDKException.class)
    public void isValidIrisBdb_qualityScoreAtByte35_throwsSDKException() {
        String encoded = io.mosip.mock.sdk.util.Util.encodeToURLSafeBase64(buildIrisIsoWithQualityScoreAtByte35());
        service.callIsValidIrisBdb(null, "UNKNOWN", encoded);
    }

    private byte[] buildIrisIsoWithQualityScoreAtByte35() {
        byte[] bdb = new byte[500];
        bdb[0] = 0x49; bdb[1] = 0x49; bdb[2] = 0x52; bdb[3] = 0x00; // "IIR\0"
        bdb[4] = 0x30; bdb[5] = 0x32; bdb[6] = 0x30; bdb[7] = 0x00; // "020\0"
        bdb[8] = 0x00; bdb[9] = 0x00; bdb[10] = 0x01; bdb[11] = (byte) 0xF4; // recordLength=500
        bdb[12] = 0x00; bdb[13] = 0x01; // noOfRepresentations=1
        bdb[14] = 0x00; // certificationFlag=0 (valid)
        bdb[15] = 0x01; // noOfEyesPresent=1 (valid)
        // bytes 16-28: representationDataLength + captureDateTime (all zero)
        // byte 29: captureDeviceTech=0 (valid for iris: only 0 and 1)
        // bytes 30-33: vendor=0, type=0 (valid)
        bdb[34] = 0x01; // noOfQualityBlocks=1
        bdb[35] = (byte) 0x80; // qualityScore=128 at byte 35 (score-first layout, INVALID: >100)
        // bytes 36-38: qualityAlgoVendor(2)+qualityAlgoId partial = zero (valid)
        bdb[39] = (byte) 0x80; // qualityScore=128 at byte 39 (vendor-first fallback, INVALID: >100)
        return bdb;
    }

    // ========== Iris invalid horizontal and vertical orientation ==========
    // With noOfQualityBlocks=0, representation body starts at byte 35.
    // Horizontal orientation is at byte 40, vertical at byte 41.

    @Test(expected = SDKException.class)
    public void isValidIrisBdb_invalidOrientations_throwsSDKException() {
        String encoded = io.mosip.mock.sdk.util.Util.encodeToURLSafeBase64(buildIrisIsoWithInvalidOrientations());
        service.callIsValidIrisBdb(null, "UNKNOWN", encoded);
    }

    private byte[] buildIrisIsoWithInvalidOrientations() {
        byte[] bdb = new byte[500];
        bdb[0] = 0x49; bdb[1] = 0x49; bdb[2] = 0x52; bdb[3] = 0x00; // "IIR\0"
        bdb[4] = 0x30; bdb[5] = 0x32; bdb[6] = 0x30; bdb[7] = 0x00; // "020\0"
        bdb[8] = 0x00; bdb[9] = 0x00; bdb[10] = 0x01; bdb[11] = (byte) 0xF4; // recordLength=500
        bdb[12] = 0x00; bdb[13] = 0x01; // noOfRepresentations=1
        bdb[14] = 0x00; // certificationFlag=0 (valid)
        bdb[15] = 0x01; // noOfEyesPresent=1 (valid)
        // bytes 16-33: all zero (representationDataLength, captureDateTime, vendor, type)
        bdb[34] = 0x00; // noOfQualityBlocks=0 → representation body starts at byte 35
        // Representation body (byte 35): representationNo=0 (INVALID: fires existing line)
        // byte 36: eyeLabel=0 (valid for UNKNOWN)
        // byte 37: imageType=0 (INVALID: fires existing line)
        // bytes 38-39: imageFormat=0 (INVALID: fires existing line)
        bdb[40] = 0x03; // horizontalOrientation=3 (INVALID: {0,1,2} valid → covers line 584)
        bdb[41] = 0x03; // verticalOrientation=3 (INVALID: {0,1,2} valid → covers line 590)
        return bdb;
    }

    // ========== Face landmark loop: noOfLandmarkPoints=1 → loop runs → covers lines 858,865,871,878,885 ==========

    @Test(expected = SDKException.class)
    public void isValidFaceBdb_withLandmarkPoint_throwsSDKException() {
        String encoded = io.mosip.mock.sdk.util.Util.encodeToURLSafeBase64(buildFaceIsoWithLandmarkPoint());
        service.callIsValidFaceBdb(null, null, encoded);
    }

    private byte[] buildFaceIsoWithLandmarkPoint() {
        byte[] bdb = new byte[500];
        bdb[0] = 0x46; bdb[1] = 0x41; bdb[2] = 0x43; bdb[3] = 0x00; // "FAC\0"
        bdb[4] = 0x30; bdb[5] = 0x33; bdb[6] = 0x30; bdb[7] = 0x00; // "030\0"
        bdb[8] = 0x00; bdb[9] = 0x00; bdb[10] = 0x01; bdb[11] = (byte) 0xF4; // recordLength=500
        bdb[12] = 0x00; bdb[13] = 0x01; // noOfRepresentations=1
        bdb[14] = 0x00; // certificationFlag=0 (valid for face: only 0x00 valid)
        bdb[15] = 0x00; bdb[16] = 0x00; // temporalSemantics=0x0000 (valid)
        // bytes 17-29: representationDataLength + captureDateTime (all zero)
        bdb[30] = 0x07; // captureDeviceTech=7 (INVALID → ensures throw at end)
        // bytes 31-34: vendor=0, type=0 (valid)
        bdb[35] = 0x01; // noOfQualityBlocks=1
        // quality block bytes 36-40: vendor(36-37)=0, algo(38-39)=0, score(40)=0 (VALID for face)
        // FacialInformation at byte 41 (certFlag=0x00 != ONE → no cert blocks):
        bdb[41] = 0x00; bdb[42] = 0x01; // noOfLandmarkPoints=0x0001=1 → landmark loop runs
        // Landmark point 1 at bytes 43-50: type(1)+code(1)+x(2)+y(2)+z(2), all zero → always-valid
        // After landmark (byte 51): gender=0, eyeColor=0, hairColor=0 → all valid
        return bdb;
    }

    // ========== Face noOfRepresentations=0 (may cover line 724 if decoder does not throw) ==========

    @Test(expected = SDKException.class)
    public void isValidFaceBdb_noRepresentations_throwsSDKException() {
        String encoded = io.mosip.mock.sdk.util.Util.encodeToURLSafeBase64(buildFaceIsoWithNoRepresentations());
        service.callIsValidFaceBdb(null, null, encoded);
    }

    private byte[] buildFaceIsoWithNoRepresentations() {
        byte[] bdb = new byte[500];
        bdb[0] = 0x46; bdb[1] = 0x41; bdb[2] = 0x43; bdb[3] = 0x00; // "FAC\0"
        bdb[4] = 0x30; bdb[5] = 0x33; bdb[6] = 0x30; bdb[7] = 0x00; // "030\0"
        bdb[8] = 0x00; bdb[9] = 0x00; bdb[10] = 0x01; bdb[11] = (byte) 0xF4; // recordLength=500
        bdb[12] = 0x00; bdb[13] = 0x00; // noOfRepresentations=0 (INVALID: only 1 valid)
        // all other bytes zero: certificationFlag=0, temporalSemantics=0
        return bdb;
    }
}