/*
 * Copyright (c) Modular Open Source Identity Platform
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */
package io.mosip.mock.sdk;

import org.junit.Assert;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;

import io.mosip.kernel.biometrics.constant.BiometricType;


import io.mosip.kernel.biometrics.constant.Match;
import io.mosip.kernel.biometrics.entities.BDBInfo;
import io.mosip.kernel.biometrics.entities.BIR;
import io.mosip.kernel.biometrics.entities.BIRInfo;
import io.mosip.kernel.biometrics.entities.BiometricRecord;
import io.mosip.kernel.biometrics.entities.RegistryIDType;
import io.mosip.kernel.biometrics.entities.VersionType;
import io.mosip.kernel.biometrics.model.MatchDecision;
import io.mosip.kernel.biometrics.model.QualityCheck;
import io.mosip.kernel.biometrics.model.Response;
import io.mosip.mock.sdk.constant.ResponseStatus;
import io.mosip.mock.sdk.exception.ConversionException;
import io.mosip.mock.sdk.exception.SDKException;
import io.mosip.mock.sdk.service.CheckQualityService;
import io.mosip.mock.sdk.service.ConvertFormatService;
import io.mosip.mock.sdk.service.ExtractTemplateService;
import io.mosip.mock.sdk.service.MatchService;

public class ServiceCoverageTest {

    // ===== CheckQualityService switch-case arms =====

    @Test
    public void checkQuality_qualityCheckFailedCode_returns403() {
        BiometricRecord record = buildRecord(BiometricType.FINGER, "Left IndexFinger", new byte[]{1});
        CheckQualityService svc = new CheckQualityService(
                record, Collections.singletonList(BiometricType.FINGER), new HashMap<>()) {
            @Override protected boolean isValidBirData(BIR bir) {
                throw new SDKException(
                        String.valueOf(ResponseStatus.QUALITY_CHECK_FAILED.getStatusCode()),
                        ResponseStatus.QUALITY_CHECK_FAILED.getStatusMessage());
            }
        };
        Response<QualityCheck> response = svc.getCheckQualityInfo();
        Assert.assertEquals(ResponseStatus.QUALITY_CHECK_FAILED.getStatusCode(),
                (int) response.getStatusCode());
    }

    @Test
    public void checkQuality_matchingBiometricFailedCode_returns405() {
        BiometricRecord record = buildRecord(BiometricType.FINGER, "Left IndexFinger", new byte[]{1});
        CheckQualityService svc = new CheckQualityService(
                record, Collections.singletonList(BiometricType.FINGER), new HashMap<>()) {
            @Override protected boolean isValidBirData(BIR bir) {
                throw new SDKException(
                        String.valueOf(ResponseStatus.MATCHING_OF_BIOMETRIC_DATA_FAILED.getStatusCode()),
                        ResponseStatus.MATCHING_OF_BIOMETRIC_DATA_FAILED.getStatusMessage());
            }
        };
        Response<QualityCheck> response = svc.getCheckQualityInfo();
        Assert.assertEquals(ResponseStatus.MATCHING_OF_BIOMETRIC_DATA_FAILED.getStatusCode(),
                (int) response.getStatusCode());
    }

    @Test
    public void checkQuality_poorDataQualityCode_returns406() {
        BiometricRecord record = buildRecord(BiometricType.FINGER, "Left IndexFinger", new byte[]{1});
        CheckQualityService svc = new CheckQualityService(
                record, Collections.singletonList(BiometricType.FINGER), new HashMap<>()) {
            @Override protected boolean isValidBirData(BIR bir) {
                throw new SDKException(
                        String.valueOf(ResponseStatus.POOR_DATA_QUALITY.getStatusCode()),
                        ResponseStatus.POOR_DATA_QUALITY.getStatusMessage());
            }
        };
        Response<QualityCheck> response = svc.getCheckQualityInfo();
        Assert.assertEquals(ResponseStatus.POOR_DATA_QUALITY.getStatusCode(),
                (int) response.getStatusCode());
    }

    @Test
    public void checkQuality_unmappedCode_hitsDefaultReturns500() {
        BiometricRecord record = buildRecord(BiometricType.FINGER, "Left IndexFinger", new byte[]{1});
        CheckQualityService svc = new CheckQualityService(
                record, Collections.singletonList(BiometricType.FINGER), new HashMap<>()) {
            @Override protected boolean isValidBirData(BIR bir) {
                throw new SDKException("999", "unmapped");
            }
        };
        Response<QualityCheck> response = svc.getCheckQualityInfo();
        Assert.assertEquals(ResponseStatus.UNKNOWN_ERROR.getStatusCode(),
                (int) response.getStatusCode());
    }

    // evaluateQuality default arm (unsupported modality SCENT)
    @Test
    public void checkQuality_scentModality_evaluateQualityDefaultCaseReturnsSuccess() {
        BiometricRecord record = buildRecord(BiometricType.SCENT, "test", new byte[]{1});
        CheckQualityService svc = new CheckQualityService(
                record, Collections.emptyList(), new HashMap<>()) {
            @Override protected boolean isValidBirData(BIR bir) { return true; }
        };
        Response<QualityCheck> response = svc.getCheckQualityInfo();
        Assert.assertEquals(ResponseStatus.SUCCESS.getStatusCode(), (int) response.getStatusCode());
        Assert.assertTrue(response.getResponse().getScores().containsKey(BiometricType.SCENT));
    }

    // null quality on segment → getAvgQualityScore throws POOR_DATA_QUALITY SDKException
    @Test
    public void checkQuality_nullQualityOnSegment_returnsPoorDataQuality() {
        BiometricRecord record = buildRecord(BiometricType.FINGER, "Left IndexFinger", new byte[]{1});
        CheckQualityService svc = new CheckQualityService(
                record, Collections.singletonList(BiometricType.FINGER), new HashMap<>()) {
            @Override protected boolean isValidBirData(BIR bir) { return true; }
        };
        Response<QualityCheck> response = svc.getCheckQualityInfo();
        Assert.assertEquals(ResponseStatus.POOR_DATA_QUALITY.getStatusCode(),
                (int) response.getStatusCode());
    }

    // ===== ExtractTemplateService switch-case arms =====

    @Test
    public void extractTemplate_qualityCheckFailedCode_returns403() {
        BiometricRecord record = buildRecord(BiometricType.FINGER, "Left IndexFinger", new byte[]{1});
        ExtractTemplateService svc = new ExtractTemplateService(
                record, Collections.singletonList(BiometricType.FINGER), new HashMap<>()) {
            @Override protected boolean isValidBirData(BIR bir) {
                throw new SDKException(
                        String.valueOf(ResponseStatus.QUALITY_CHECK_FAILED.getStatusCode()),
                        ResponseStatus.QUALITY_CHECK_FAILED.getStatusMessage());
            }
        };
        Response<BiometricRecord> response = svc.getExtractTemplateInfo();
        Assert.assertEquals(ResponseStatus.QUALITY_CHECK_FAILED.getStatusCode(),
                (int) response.getStatusCode());
    }

    @Test
    public void extractTemplate_matchingBiometricFailedCode_returns405() {
        BiometricRecord record = buildRecord(BiometricType.FINGER, "Left IndexFinger", new byte[]{1});
        ExtractTemplateService svc = new ExtractTemplateService(
                record, Collections.singletonList(BiometricType.FINGER), new HashMap<>()) {
            @Override protected boolean isValidBirData(BIR bir) {
                throw new SDKException(
                        String.valueOf(ResponseStatus.MATCHING_OF_BIOMETRIC_DATA_FAILED.getStatusCode()),
                        ResponseStatus.MATCHING_OF_BIOMETRIC_DATA_FAILED.getStatusMessage());
            }
        };
        Response<BiometricRecord> response = svc.getExtractTemplateInfo();
        Assert.assertEquals(ResponseStatus.MATCHING_OF_BIOMETRIC_DATA_FAILED.getStatusCode(),
                (int) response.getStatusCode());
    }

    @Test
    public void extractTemplate_poorDataQualityCode_returns406() {
        BiometricRecord record = buildRecord(BiometricType.FINGER, "Left IndexFinger", new byte[]{1});
        ExtractTemplateService svc = new ExtractTemplateService(
                record, Collections.singletonList(BiometricType.FINGER), new HashMap<>()) {
            @Override protected boolean isValidBirData(BIR bir) {
                throw new SDKException(
                        String.valueOf(ResponseStatus.POOR_DATA_QUALITY.getStatusCode()),
                        ResponseStatus.POOR_DATA_QUALITY.getStatusMessage());
            }
        };
        Response<BiometricRecord> response = svc.getExtractTemplateInfo();
        Assert.assertEquals(ResponseStatus.POOR_DATA_QUALITY.getStatusCode(),
                (int) response.getStatusCode());
    }

    @Test
    public void extractTemplate_unmappedCode_hitsDefaultReturns500() {
        BiometricRecord record = buildRecord(BiometricType.FINGER, "Left IndexFinger", new byte[]{1});
        ExtractTemplateService svc = new ExtractTemplateService(
                record, Collections.singletonList(BiometricType.FINGER), new HashMap<>()) {
            @Override protected boolean isValidBirData(BIR bir) {
                throw new SDKException("999", "unmapped");
            }
        };
        Response<BiometricRecord> response = svc.getExtractTemplateInfo();
        Assert.assertEquals(ResponseStatus.UNKNOWN_ERROR.getStatusCode(),
                (int) response.getStatusCode());
    }

    // format type != "7": format block entered but conversion NOT applied
    @Test
    public void extractTemplate_formatTypeNotSeven_doesNotConvertType() {
        BIR.BIRBuilder builder = new BIR.BIRBuilder();
        builder.withVersion(new VersionType(1, 1));
        builder.withCbeffversion(new VersionType(1, 1));
        BDBInfo.BDBInfoBuilder bdbInfoBuilder = new BDBInfo.BDBInfoBuilder();
        bdbInfoBuilder.withType(Collections.singletonList(BiometricType.FINGER));
        bdbInfoBuilder.withSubtype(Collections.singletonList("Left IndexFinger"));
        BDBInfo bdbInfo = new BDBInfo(bdbInfoBuilder);
        RegistryIDType fmt = new RegistryIDType();
        fmt.setType("8");
        bdbInfo.setFormat(fmt);
        builder.withBdbInfo(bdbInfo);
        builder.withBirInfo(new BIRInfo(new BIRInfo.BIRInfoBuilder().withCreator("test")));
        builder.withBdb(new byte[]{1});
        BiometricRecord record = new BiometricRecord();
        record.setSegments(Collections.singletonList(new BIR(builder)));

        ExtractTemplateService svc = new ExtractTemplateService(
                record, Collections.singletonList(BiometricType.FINGER), new HashMap<>()) {
            @Override protected boolean isValidBirData(BIR bir) { return true; }
        };
        Response<BiometricRecord> response = svc.getExtractTemplateInfo();
        Assert.assertEquals(ResponseStatus.SUCCESS.getStatusCode(), (int) response.getStatusCode());
        Assert.assertEquals("8",
                response.getResponse().getSegments().get(0).getBdbInfo().getFormat().getType());
    }

    // format type == null: inner condition false, type unchanged
    @Test
    public void extractTemplate_formatTypeNull_doesNotConvertType() {
        BIR.BIRBuilder builder = new BIR.BIRBuilder();
        builder.withVersion(new VersionType(1, 1));
        builder.withCbeffversion(new VersionType(1, 1));
        BDBInfo.BDBInfoBuilder bdbInfoBuilder = new BDBInfo.BDBInfoBuilder();
        bdbInfoBuilder.withType(Collections.singletonList(BiometricType.FINGER));
        bdbInfoBuilder.withSubtype(Collections.singletonList("Left IndexFinger"));
        BDBInfo bdbInfo = new BDBInfo(bdbInfoBuilder);
        RegistryIDType fmt = new RegistryIDType();
        fmt.setType(null);
        bdbInfo.setFormat(fmt);
        builder.withBdbInfo(bdbInfo);
        builder.withBirInfo(new BIRInfo(new BIRInfo.BIRInfoBuilder().withCreator("test")));
        builder.withBdb(new byte[]{1});
        BiometricRecord record = new BiometricRecord();
        record.setSegments(Collections.singletonList(new BIR(builder)));

        ExtractTemplateService svc = new ExtractTemplateService(
                record, Collections.singletonList(BiometricType.FINGER), new HashMap<>()) {
            @Override protected boolean isValidBirData(BIR bir) { return true; }
        };
        Response<BiometricRecord> response = svc.getExtractTemplateInfo();
        Assert.assertEquals(ResponseStatus.SUCCESS.getStatusCode(), (int) response.getStatusCode());
        Assert.assertNull(
                response.getResponse().getSegments().get(0).getBdbInfo().getFormat().getType());
    }

    // ===== MatchService switch-case arms =====

    @Test
    public void match_qualityCheckFailedCode_returns403() {
        BiometricRecord sample = buildRecord(BiometricType.FINGER, "Left IndexFinger", new byte[]{1});
        BiometricRecord gallery = buildRecord(BiometricType.FINGER, "Left IndexFinger", new byte[]{1});
        MatchService svc = new MatchService(sample, new BiometricRecord[]{gallery},
                Collections.singletonList(BiometricType.FINGER), new HashMap<>()) {
            @Override protected boolean isValidBirData(BIR bir) {
                throw new SDKException(
                        String.valueOf(ResponseStatus.QUALITY_CHECK_FAILED.getStatusCode()),
                        ResponseStatus.QUALITY_CHECK_FAILED.getStatusMessage());
            }
        };
        Response<MatchDecision[]> response = svc.getMatchDecisionInfo();
        Assert.assertEquals(ResponseStatus.QUALITY_CHECK_FAILED.getStatusCode(),
                (int) response.getStatusCode());
    }

    @Test
    public void match_matchingBiometricFailedCode_returns405() {
        BiometricRecord sample = buildRecord(BiometricType.FINGER, "Left IndexFinger", new byte[]{1});
        BiometricRecord gallery = buildRecord(BiometricType.FINGER, "Left IndexFinger", new byte[]{1});
        MatchService svc = new MatchService(sample, new BiometricRecord[]{gallery},
                Collections.singletonList(BiometricType.FINGER), new HashMap<>()) {
            @Override protected boolean isValidBirData(BIR bir) {
                throw new SDKException(
                        String.valueOf(ResponseStatus.MATCHING_OF_BIOMETRIC_DATA_FAILED.getStatusCode()),
                        ResponseStatus.MATCHING_OF_BIOMETRIC_DATA_FAILED.getStatusMessage());
            }
        };
        Response<MatchDecision[]> response = svc.getMatchDecisionInfo();
        Assert.assertEquals(ResponseStatus.MATCHING_OF_BIOMETRIC_DATA_FAILED.getStatusCode(),
                (int) response.getStatusCode());
    }

    @Test
    public void match_poorDataQualityCode_returns406() {
        BiometricRecord sample = buildRecord(BiometricType.FINGER, "Left IndexFinger", new byte[]{1});
        BiometricRecord gallery = buildRecord(BiometricType.FINGER, "Left IndexFinger", new byte[]{1});
        MatchService svc = new MatchService(sample, new BiometricRecord[]{gallery},
                Collections.singletonList(BiometricType.FINGER), new HashMap<>()) {
            @Override protected boolean isValidBirData(BIR bir) {
                throw new SDKException(
                        String.valueOf(ResponseStatus.POOR_DATA_QUALITY.getStatusCode()),
                        ResponseStatus.POOR_DATA_QUALITY.getStatusMessage());
            }
        };
        Response<MatchDecision[]> response = svc.getMatchDecisionInfo();
        Assert.assertEquals(ResponseStatus.POOR_DATA_QUALITY.getStatusCode(),
                (int) response.getStatusCode());
    }

    @Test
    public void match_unmappedCode_hitsDefaultReturns500() {
        BiometricRecord sample = buildRecord(BiometricType.FINGER, "Left IndexFinger", new byte[]{1});
        BiometricRecord gallery = buildRecord(BiometricType.FINGER, "Left IndexFinger", new byte[]{1});
        MatchService svc = new MatchService(sample, new BiometricRecord[]{gallery},
                Collections.singletonList(BiometricType.FINGER), new HashMap<>()) {
            @Override protected boolean isValidBirData(BIR bir) {
                throw new SDKException("999", "unmapped");
            }
        };
        Response<MatchDecision[]> response = svc.getMatchDecisionInfo();
        Assert.assertEquals(ResponseStatus.UNKNOWN_ERROR.getStatusCode(),
                (int) response.getStatusCode());
    }

    // ===== ConvertFormatService switch-case arms =====

    @Test
    public void convertFormat_qualityCheckFailedCode_returns403() {
        BiometricRecord record = buildRecord(BiometricType.FINGER, "Left IndexFinger", new byte[]{1});
        ConvertFormatService svc = new ConvertFormatService(record, "ISO19794_4_2011", "IMAGE/JPEG",
                new HashMap<>(), new HashMap<>(),
                Collections.singletonList(BiometricType.FINGER)) {
            @Override protected boolean isValidBirData(BIR bir) {
                throw new SDKException(
                        String.valueOf(ResponseStatus.QUALITY_CHECK_FAILED.getStatusCode()),
                        ResponseStatus.QUALITY_CHECK_FAILED.getStatusMessage());
            }
        };
        Response<BiometricRecord> response = svc.getConvertFormatInfo();
        Assert.assertEquals(ResponseStatus.QUALITY_CHECK_FAILED.getStatusCode(),
                (int) response.getStatusCode());
    }

    @Test
    public void convertFormat_matchingBiometricFailedCode_returns405() {
        BiometricRecord record = buildRecord(BiometricType.FINGER, "Left IndexFinger", new byte[]{1});
        ConvertFormatService svc = new ConvertFormatService(record, "ISO19794_4_2011", "IMAGE/JPEG",
                new HashMap<>(), new HashMap<>(),
                Collections.singletonList(BiometricType.FINGER)) {
            @Override protected boolean isValidBirData(BIR bir) {
                throw new SDKException(
                        String.valueOf(ResponseStatus.MATCHING_OF_BIOMETRIC_DATA_FAILED.getStatusCode()),
                        ResponseStatus.MATCHING_OF_BIOMETRIC_DATA_FAILED.getStatusMessage());
            }
        };
        Response<BiometricRecord> response = svc.getConvertFormatInfo();
        Assert.assertEquals(ResponseStatus.MATCHING_OF_BIOMETRIC_DATA_FAILED.getStatusCode(),
                (int) response.getStatusCode());
    }

    @Test
    public void convertFormat_poorDataQualityCode_returns406() {
        BiometricRecord record = buildRecord(BiometricType.FINGER, "Left IndexFinger", new byte[]{1});
        ConvertFormatService svc = new ConvertFormatService(record, "ISO19794_4_2011", "IMAGE/JPEG",
                new HashMap<>(), new HashMap<>(),
                Collections.singletonList(BiometricType.FINGER)) {
            @Override protected boolean isValidBirData(BIR bir) {
                throw new SDKException(
                        String.valueOf(ResponseStatus.POOR_DATA_QUALITY.getStatusCode()),
                        ResponseStatus.POOR_DATA_QUALITY.getStatusMessage());
            }
        };
        Response<BiometricRecord> response = svc.getConvertFormatInfo();
        Assert.assertEquals(ResponseStatus.POOR_DATA_QUALITY.getStatusCode(),
                (int) response.getStatusCode());
    }

    @Test
    public void convertFormat_unmappedCode_hitsDefaultReturns500() {
        BiometricRecord record = buildRecord(BiometricType.FINGER, "Left IndexFinger", new byte[]{1});
        ConvertFormatService svc = new ConvertFormatService(record, "ISO19794_4_2011", "IMAGE/JPEG",
                new HashMap<>(), new HashMap<>(),
                Collections.singletonList(BiometricType.FINGER)) {
            @Override protected boolean isValidBirData(BIR bir) {
                throw new SDKException("999", "unmapped");
            }
        };
        Response<BiometricRecord> response = svc.getConvertFormatInfo();
        Assert.assertEquals(ResponseStatus.UNKNOWN_ERROR.getStatusCode(),
                (int) response.getStatusCode());
    }

    // ConversionException SOURCE_CAN_NOT_BE_EMPTY_OR_NULL (null BDB encodes to null → converter throws)
    @Test
    public void convertFormat_nullBdbBypassesValidation_conversionExceptionSourceEmpty_returns404() {
        BiometricRecord record = buildRecord(BiometricType.FINGER, "Left IndexFinger", null);
        ConvertFormatService svc = new ConvertFormatService(record, "ISO19794_4_2011", "IMAGE/JPEG",
                new HashMap<>(), new HashMap<>(),
                Collections.singletonList(BiometricType.FINGER)) {
            @Override protected boolean isValidBirData(BIR bir) { return true; }
        };
        Response<BiometricRecord> response = svc.getConvertFormatInfo();
        Assert.assertEquals(ResponseStatus.BIOMETRIC_NOT_FOUND_IN_CBEFF.getStatusCode(),
                (int) response.getStatusCode());
    }

    // ===== MatchService comparers: one-null paths (sample has segments, gallery lacks that modality) =====

    @Test
    public void match_fingerGalleryHasNoFinger_returnsSuccess() {
        BiometricRecord sample = buildRecord(BiometricType.FINGER, "Left IndexFinger", new byte[]{1});
        BiometricRecord gallery = buildRecord(BiometricType.FACE, null, new byte[]{1});
        MatchService svc = new MatchService(sample, new BiometricRecord[]{gallery},
                Collections.singletonList(BiometricType.FINGER), new HashMap<>());
        Response<MatchDecision[]> response = svc.getMatchDecisionInfo();
        Assert.assertNotNull(response);
        Assert.assertEquals(ResponseStatus.SUCCESS.getStatusCode(), (int) response.getStatusCode());
    }

    @Test
    public void match_irisGalleryHasNoIris_returnsSuccess() {
        BiometricRecord sample = buildRecord(BiometricType.IRIS, "Left", new byte[]{1});
        BiometricRecord gallery = buildRecord(BiometricType.FACE, null, new byte[]{1});
        MatchService svc = new MatchService(sample, new BiometricRecord[]{gallery},
                Collections.singletonList(BiometricType.IRIS), new HashMap<>());
        Response<MatchDecision[]> response = svc.getMatchDecisionInfo();
        Assert.assertNotNull(response);
        Assert.assertEquals(ResponseStatus.SUCCESS.getStatusCode(), (int) response.getStatusCode());
    }

    @Test
    public void match_faceGalleryHasNoFace_returnsSuccess() {
        BiometricRecord sample = buildRecord(BiometricType.FACE, null, new byte[]{1});
        BiometricRecord gallery = buildRecord(BiometricType.FINGER, "Left IndexFinger", new byte[]{1});
        MatchService svc = new MatchService(sample, new BiometricRecord[]{gallery},
                Collections.singletonList(BiometricType.FACE), new HashMap<>());
        Response<MatchDecision[]> response = svc.getMatchDecisionInfo();
        Assert.assertNotNull(response);
        Assert.assertEquals(ResponseStatus.SUCCESS.getStatusCode(), (int) response.getStatusCode());
    }

    // ===== MatchService comparers: UNKNOWN subtype enters else-branch =====

    @Test
    public void match_unknownFingerSubtype_coversElseBranch() {
        byte[] sameBdb = new byte[]{1, 2, 3};
        BiometricRecord sample = buildRecord(BiometricType.FINGER, "UNKNOWN", sameBdb);
        BiometricRecord gallery = buildRecord(BiometricType.FINGER, "Left IndexFinger", sameBdb);
        MatchService svc = new MatchService(sample, new BiometricRecord[]{gallery},
                Collections.singletonList(BiometricType.FINGER), new HashMap<>()) {
            @Override protected boolean isValidBirData(BIR bir) { return true; }
        };
        Response<MatchDecision[]> response = svc.getMatchDecisionInfo();
        Assert.assertNotNull(response);
        Assert.assertEquals(ResponseStatus.SUCCESS.getStatusCode(), (int) response.getStatusCode());
    }

    @Test
    public void match_unknownIrisSubtype_coversElseBranch() {
        byte[] sameBdb = new byte[]{1, 2, 3};
        BiometricRecord sample = buildRecord(BiometricType.IRIS, "UNKNOWN", sameBdb);
        BiometricRecord gallery = buildRecord(BiometricType.IRIS, "Left", sameBdb);
        MatchService svc = new MatchService(sample, new BiometricRecord[]{gallery},
                Collections.singletonList(BiometricType.IRIS), new HashMap<>()) {
            @Override protected boolean isValidBirData(BIR bir) { return true; }
        };
        Response<MatchDecision[]> response = svc.getMatchDecisionInfo();
        Assert.assertNotNull(response);
        Assert.assertEquals(ResponseStatus.SUCCESS.getStatusCode(), (int) response.getStatusCode());
    }

    // ===== MatchService comparers: isValidBirData returns false → break → matched empty → ERROR =====

    @Test
    public void match_isValidBirDataFalse_finger_errorDecision() {
        BiometricRecord sample = buildRecord(BiometricType.FINGER, "Left IndexFinger", new byte[]{1});
        BiometricRecord gallery = buildRecord(BiometricType.FINGER, "Left IndexFinger", new byte[]{1});
        MatchService svc = new MatchService(sample, new BiometricRecord[]{gallery},
                Collections.singletonList(BiometricType.FINGER), new HashMap<>()) {
            @Override protected boolean isValidBirData(BIR bir) { return false; }
        };
        Response<MatchDecision[]> response = svc.getMatchDecisionInfo();
        Assert.assertNotNull(response);
        Assert.assertEquals(ResponseStatus.SUCCESS.getStatusCode(), (int) response.getStatusCode());
        Assert.assertNotNull(response.getResponse());
        Assert.assertEquals(Match.ERROR, response.getResponse()[0].getDecisions().get(BiometricType.FINGER).getMatch());
    }

    @Test
    public void match_isValidBirDataFalse_iris_errorDecision() {
        BiometricRecord sample = buildRecord(BiometricType.IRIS, "Left", new byte[]{1});
        BiometricRecord gallery = buildRecord(BiometricType.IRIS, "Left", new byte[]{1});
        MatchService svc = new MatchService(sample, new BiometricRecord[]{gallery},
                Collections.singletonList(BiometricType.IRIS), new HashMap<>()) {
            @Override protected boolean isValidBirData(BIR bir) { return false; }
        };
        Response<MatchDecision[]> response = svc.getMatchDecisionInfo();
        Assert.assertNotNull(response);
        Assert.assertEquals(ResponseStatus.SUCCESS.getStatusCode(), (int) response.getStatusCode());
        Assert.assertNotNull(response.getResponse());
        Assert.assertEquals(Match.ERROR, response.getResponse()[0].getDecisions().get(BiometricType.IRIS).getMatch());
    }

    @Test
    public void match_isValidBirDataFalse_face_errorDecision() {
        BiometricRecord sample = buildRecord(BiometricType.FACE, null, new byte[]{1});
        BiometricRecord gallery = buildRecord(BiometricType.FACE, null, new byte[]{1});
        MatchService svc = new MatchService(sample, new BiometricRecord[]{gallery},
                Collections.singletonList(BiometricType.FACE), new HashMap<>()) {
            @Override protected boolean isValidBirData(BIR bir) { return false; }
        };
        Response<MatchDecision[]> response = svc.getMatchDecisionInfo();
        Assert.assertNotNull(response);
        Assert.assertEquals(ResponseStatus.SUCCESS.getStatusCode(), (int) response.getStatusCode());
        Assert.assertNotNull(response.getResponse());
        Assert.assertEquals(Match.ERROR, response.getResponse()[0].getDecisions().get(BiometricType.FACE).getMatch());
    }

    // ===== ConvertFormatService: ConversionException INVALID_SOURCE (covers switch lines 148-162) =====
    // SourceFormatCode.fromCode("UNKNOWN_FORMAT") throws ConversionException(INVALID_SOURCE) before the values loop

    @Test
    public void convertFormat_unknownSourceFormat_returnsInvalidInput() {
        BiometricRecord record = buildRecord(BiometricType.FINGER, "Left IndexFinger", new byte[]{1});
        ConvertFormatService svc = new ConvertFormatService(record, "UNKNOWN_FORMAT", "IMAGE/JPEG",
                new HashMap<>(), new HashMap<>(),
                Collections.singletonList(BiometricType.FINGER)) {
            @Override protected boolean isValidBirData(BIR bir) { return true; }
        };
        Response<BiometricRecord> response = svc.getConvertFormatInfo();
        Assert.assertNotNull(response);
        Assert.assertEquals(ResponseStatus.INVALID_INPUT.getStatusCode(), (int) response.getStatusCode());
    }

    // ===== ConvertFormatService: catch(Exception) from IndexOutOfBoundsException on empty type list =====

    @Test
    public void convertFormat_emptyTypeList_catchesException_returnsUnknownError() {
        BIR.BIRBuilder builder = new BIR.BIRBuilder();
        builder.withVersion(new VersionType(1, 1));
        builder.withCbeffversion(new VersionType(1, 1));
        BDBInfo.BDBInfoBuilder bdbInfoBuilder = new BDBInfo.BDBInfoBuilder();
        bdbInfoBuilder.withType(Collections.emptyList());
        bdbInfoBuilder.withSubtype(Collections.emptyList());
        builder.withBdbInfo(new BDBInfo(bdbInfoBuilder));
        builder.withBdb(new byte[]{1});
        BiometricRecord record = new BiometricRecord();
        record.setSegments(Collections.singletonList(new BIR(builder)));

        ConvertFormatService svc = new ConvertFormatService(record, "ISO19794_4_2011", "IMAGE/JPEG",
                new HashMap<>(), new HashMap<>(),
                Collections.singletonList(BiometricType.FINGER)) {
            @Override protected boolean isValidBirData(BIR bir) { return true; }
        };
        Response<BiometricRecord> response = svc.getConvertFormatInfo();
        Assert.assertNotNull(response);
        Assert.assertEquals(ResponseStatus.UNKNOWN_ERROR.getStatusCode(), (int) response.getStatusCode());
    }

    // ===== ConvertFormatService: success path via isValidBirData=false + 2-subtype BIR =====
    // isValidBirData=false → values={} → convert({}) returns {} → second loop runs (lines 79-104)
    // second loop processes 2-subtype BIR → covers lines 87-88 (2-subtype branch in second loop)
    // NOTE: must use mutable list because line 100 calls birList.set()

    @Test
    public void convertFormat_isValidBirDataFalse_twoSubtype_coversSuccessPath() {
        BIR.BIRBuilder builder = new BIR.BIRBuilder();
        builder.withVersion(new VersionType(1, 1));
        builder.withCbeffversion(new VersionType(1, 1));
        BDBInfo.BDBInfoBuilder bdbInfoBuilder = new BDBInfo.BDBInfoBuilder();
        bdbInfoBuilder.withType(Collections.singletonList(BiometricType.FINGER));
        bdbInfoBuilder.withSubtype(Arrays.asList("Left", "IndexFinger"));
        builder.withBdbInfo(new BDBInfo(bdbInfoBuilder));
        builder.withBdb(new byte[]{1});
        BiometricRecord record = new BiometricRecord();
        ArrayList<BIR> segments = new ArrayList<>();
        segments.add(new BIR(builder));
        record.setSegments(segments);

        ConvertFormatService svc = new ConvertFormatService(record, "ISO19794_4_2011", "IMAGE/JPEG",
                new HashMap<>(), new HashMap<>(),
                Collections.singletonList(BiometricType.FINGER)) {
            @Override protected boolean isValidBirData(BIR bir) { return false; }
        };
        Response<BiometricRecord> response = svc.getConvertFormatInfo();
        Assert.assertNotNull(response);
        Assert.assertEquals(ResponseStatus.SUCCESS.getStatusCode(), (int) response.getStatusCode());
    }

    // ===== ConvertFormatService: isValidBirData=true + 2-subtype covers first-loop lines 63-64 =====
    // null bdb → convert() throws SOURCE_CAN_NOT_BE_EMPTY_OR_NULL (before OpenCV loads) → 404

    @Test
    public void convertFormat_twoSubtypesFirstLoop_coversLines63_64() {
        BIR.BIRBuilder builder = new BIR.BIRBuilder();
        builder.withVersion(new VersionType(1, 1));
        builder.withCbeffversion(new VersionType(1, 1));
        BDBInfo.BDBInfoBuilder bdbInfoBuilder = new BDBInfo.BDBInfoBuilder();
        bdbInfoBuilder.withType(Collections.singletonList(BiometricType.FINGER));
        bdbInfoBuilder.withSubtype(Arrays.asList("Left", "IndexFinger"));
        builder.withBdbInfo(new BDBInfo(bdbInfoBuilder));
        // No withBdb() → bdb is null → Util.encodeToURLSafeBase64(null) → SOURCE_CAN_NOT_BE_EMPTY_OR_NULL
        BiometricRecord record = new BiometricRecord();
        record.setSegments(Collections.singletonList(new BIR(builder)));

        ConvertFormatService svc = new ConvertFormatService(record, "ISO19794_4_2011", "IMAGE/JPEG",
                new HashMap<>(), new HashMap<>(),
                Collections.singletonList(BiometricType.FINGER)) {
            @Override protected boolean isValidBirData(BIR bir) { return true; }
        };
        Response<BiometricRecord> response = svc.getConvertFormatInfo();
        Assert.assertNotNull(response);
        Assert.assertEquals(ResponseStatus.BIOMETRIC_NOT_FOUND_IN_CBEFF.getStatusCode(), (int) response.getStatusCode());
    }

    // ===== ConvertFormatService: ConversionException with unrecognized code → default (lines 169-172) =====
    // fromErrorCode() returns TECHNICAL_ERROR_EXCEPTION fallback → not in switch → default fires

    @Test
    public void convertFormat_conversionExceptionDefault_coversLines169to172() {
        BiometricRecord record = buildRecord(BiometricType.FINGER, "Left IndexFinger", new byte[]{1});
        ConvertFormatService svc = new ConvertFormatService(record, "ISO19794_4_2011", "IMAGE/JPEG",
                new HashMap<>(), new HashMap<>(),
                Collections.singletonList(BiometricType.FINGER)) {
            @Override protected boolean isValidBirData(BIR bir) {
                throw new ConversionException("UNRECOGNIZED_CODE_XYZ", "test unrecognized code");
            }
        };
        Response<BiometricRecord> response = svc.getConvertFormatInfo();
        Assert.assertNotNull(response);
        Assert.assertEquals(ResponseStatus.UNKNOWN_ERROR.getStatusCode(), (int) response.getStatusCode());
    }

    // ===== ConvertFormatService: SDKException INVALID_INPUT covers lines 108-112 =====

    @Test
    public void convertFormat_sdkExceptionInvalidInput_coversLines108to112() {
        BiometricRecord record = buildRecord(BiometricType.FINGER, "Left IndexFinger", new byte[]{1});
        ConvertFormatService svc = new ConvertFormatService(record, "ISO19794_4_2011", "IMAGE/JPEG",
                new HashMap<>(), new HashMap<>(),
                Collections.singletonList(BiometricType.FINGER)) {
            @Override protected boolean isValidBirData(BIR bir) {
                throw new SDKException(
                        String.valueOf(ResponseStatus.INVALID_INPUT.getStatusCode()),
                        ResponseStatus.INVALID_INPUT.getStatusMessage());
            }
        };
        Response<BiometricRecord> response = svc.getConvertFormatInfo();
        Assert.assertNotNull(response);
        Assert.assertEquals(ResponseStatus.INVALID_INPUT.getStatusCode(), (int) response.getStatusCode());
    }

    // ===== MatchService: UNKNOWN finger subtype compareHash=false path (lines 229-234) =====

    @Test
    public void match_unknownFingerSubtype_notMatched() {
        BiometricRecord sample = buildRecord(BiometricType.FINGER, "UNKNOWN", new byte[]{4, 5, 6});
        BiometricRecord gallery = buildRecord(BiometricType.FINGER, "UNKNOWN", new byte[]{1, 2, 3});
        MatchService svc = new MatchService(sample, new BiometricRecord[]{gallery},
                Collections.singletonList(BiometricType.FINGER), new HashMap<>()) {
            @Override protected boolean isValidBirData(BIR bir) { return true; }
        };
        Response<MatchDecision[]> response = svc.getMatchDecisionInfo();
        Assert.assertNotNull(response);
        Assert.assertEquals(ResponseStatus.SUCCESS.getStatusCode(), (int) response.getStatusCode());
        Assert.assertNotNull(response.getResponse());
        Assert.assertEquals(Match.NOT_MATCHED, response.getResponse()[0].getDecisions().get(BiometricType.FINGER).getMatch());
    }

    // ===== MatchService: UNKNOWN iris subtype compareHash=false path =====

    @Test
    public void match_unknownIrisSubtype_notMatched() {
        BiometricRecord sample = buildRecord(BiometricType.IRIS, "UNKNOWN", new byte[]{4, 5, 6});
        BiometricRecord gallery = buildRecord(BiometricType.IRIS, "UNKNOWN", new byte[]{1, 2, 3});
        MatchService svc = new MatchService(sample, new BiometricRecord[]{gallery},
                Collections.singletonList(BiometricType.IRIS), new HashMap<>()) {
            @Override protected boolean isValidBirData(BIR bir) { return true; }
        };
        Response<MatchDecision[]> response = svc.getMatchDecisionInfo();
        Assert.assertNotNull(response);
        Assert.assertEquals(ResponseStatus.SUCCESS.getStatusCode(), (int) response.getStatusCode());
        Assert.assertNotNull(response.getResponse());
        Assert.assertEquals(Match.NOT_MATCHED, response.getResponse()[0].getDecisions().get(BiometricType.IRIS).getMatch());
    }

    // ===== MatchService: compareModality default case (lines 138-143) via SCENT modality =====

    @Test
    public void match_unsupportedModality_defaultCase() {
        BiometricRecord sample = buildRecord(BiometricType.SCENT, "UNKNOWN", new byte[]{1});
        BiometricRecord gallery = buildRecord(BiometricType.SCENT, "UNKNOWN", new byte[]{2});
        MatchService svc = new MatchService(sample, new BiometricRecord[]{gallery},
                Collections.singletonList(BiometricType.SCENT), new HashMap<>()) {
            @Override protected boolean isValidBirData(BIR bir) { return true; }
        };
        Response<MatchDecision[]> response = svc.getMatchDecisionInfo();
        Assert.assertNotNull(response);
        Assert.assertEquals(ResponseStatus.SUCCESS.getStatusCode(), (int) response.getStatusCode());
    }

    // ===== Helpers =====

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

    private BiometricRecord buildRecord(BiometricType type, String subtype, byte[] bdb) {
        BiometricRecord record = new BiometricRecord();
        record.setSegments(Collections.singletonList(buildBIR(type, subtype, bdb)));
        return record;
    }
}
