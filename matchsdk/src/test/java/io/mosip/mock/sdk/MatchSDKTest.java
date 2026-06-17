package io.mosip.mock.sdk;

import static java.lang.Integer.parseInt;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import io.mosip.kernel.biometrics.constant.BiometricType;
import io.mosip.kernel.biometrics.constant.Match;
import io.mosip.kernel.biometrics.constant.QualityType;
import io.mosip.kernel.biometrics.entities.BDBInfo;
import io.mosip.kernel.biometrics.entities.BIR;
import io.mosip.kernel.biometrics.entities.BiometricRecord;
import io.mosip.kernel.biometrics.entities.VersionType;
import io.mosip.kernel.biometrics.model.Decision;
import io.mosip.kernel.biometrics.model.MatchDecision;
import io.mosip.kernel.biometrics.model.Response;
import io.mosip.mock.sdk.constant.ResponseStatus;
import io.mosip.mock.sdk.impl.SampleSDK;
import io.mosip.mock.sdk.util.Util;

public class MatchSDKTest {

    private final Logger LOGGER = LoggerFactory.getLogger(MatchSDKTest.class);

    private String testIrisNoMatchPath;
    private String testMatchSDKPath;
    private String testMatchSDKMatchPath;
    private String testFaceNoMatchPath;
    private String testFingerNoMatchPath;
    private String testFingerPath;
    private String testMoreFingersPath;
    private String testNoSampleMatchPath;
    private String testNoGalleryMatchPath;

    @Before
    public void setup() {
        testIrisNoMatchPath = Objects.requireNonNull(MatchSDKTest.class.getResource("/sample_files/test_sdk_iris_no_match.xml")).getPath();
        testMatchSDKPath = Objects.requireNonNull(MatchSDKTest.class.getResource("/sample_files/test_sdk.xml")).getPath();
        testMatchSDKMatchPath = Objects.requireNonNull(MatchSDKTest.class.getResource("/sample_files/test_sdk_match.xml")).getPath();
        testFaceNoMatchPath = Objects.requireNonNull(MatchSDKTest.class.getResource("/sample_files/test_sdk_face_no_match.xml")).getPath();
        testFingerNoMatchPath = Objects.requireNonNull(MatchSDKTest.class.getResource("/sample_files/test_sdk_finger_no_match.xml")).getPath();
        testFingerPath = Objects.requireNonNull(MatchSDKTest.class.getResource("/sample_files/test_sdk_finger.xml")).getPath();
        testMoreFingersPath = Objects.requireNonNull(MatchSDKTest.class.getResource("/sample_files/test_sdk_more_fingers.xml")).getPath();
        testNoSampleMatchPath = Objects.requireNonNull(MatchSDKTest.class.getResource("/sample_files/test_sdk_no_matching_sample.xml")).getPath();
        testNoGalleryMatchPath = Objects.requireNonNull(MatchSDKTest.class.getResource("/sample_files/test_sdk_no_matching_gallery.xml")).getPath();
    }

    @Test
    public void match_sameIrisBiometrics_returnsMatched() {
        try {
            List<BiometricType> modalitiesToMatch = new ArrayList<BiometricType>() {{
                add(BiometricType.IRIS);
            }};
            BiometricRecord[] gallery = new BiometricRecord[1];
            BiometricRecord sampleRecord = xmlFileToBiometricRecord(testMatchSDKPath);
            gallery[0] = xmlFileToBiometricRecord(testMatchSDKMatchPath);

            Response<MatchDecision
                    []> response = new SampleSDK().match(sampleRecord, gallery, modalitiesToMatch, new HashMap<>());

            Assert.assertNotNull(response);
            Assert.assertNotNull(response.getResponse());
            for (MatchDecision decision : response.getResponse()) {
                Map<BiometricType, Decision> decisions = decision.getDecisions();
                Assert.assertEquals(Match.MATCHED.toString(),
                        Objects.requireNonNull(decisions.get(BiometricType.IRIS)).getMatch().toString());
            }
        } catch (ParserConfigurationException | IOException | SAXException e) {
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void match_differentIrisBiometrics_returnsNotMatched() {
        try {
            List<BiometricType> modalitiesToMatch = new ArrayList<BiometricType>() {{
                add(BiometricType.IRIS);
            }};
            BiometricRecord[] gallery = new BiometricRecord[1];
            BiometricRecord sampleRecord = xmlFileToBiometricRecord(testMatchSDKPath);
            gallery[0] = xmlFileToBiometricRecord(testIrisNoMatchPath);

            Response<MatchDecision[]> response = new SampleSDK().match(sampleRecord, gallery, modalitiesToMatch, new HashMap<>());

            Assert.assertNotNull(response);
            Assert.assertNotNull(response.getResponse());
            for (MatchDecision decision : response.getResponse()) {
                Map<BiometricType, Decision> decisions = decision.getDecisions();
                Assert.assertEquals(Match.NOT_MATCHED.toString(),
                        Objects.requireNonNull(decisions.get(BiometricType.IRIS)).getMatch().toString());
            }
        } catch (ParserConfigurationException | IOException | SAXException e) {
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void match_allModalities_returnsMatched() {
        try {
            List<BiometricType> modalitiesToMatch = new ArrayList<BiometricType>() {{
                add(BiometricType.FACE);
                add(BiometricType.FINGER);
                add(BiometricType.IRIS);
            }};
            BiometricRecord[] gallery = new BiometricRecord[1];
            BiometricRecord sampleRecord = xmlFileToBiometricRecord(testMatchSDKPath);
            gallery[0] = xmlFileToBiometricRecord(testMatchSDKMatchPath);

            Response<MatchDecision[]> response = new SampleSDK().match(sampleRecord, gallery, modalitiesToMatch, new HashMap<>());

            Assert.assertNotNull(response);
            Assert.assertNotNull(response.getResponse());
            for (MatchDecision decision : response.getResponse()) {
                Map<BiometricType, Decision> decisions = decision.getDecisions();
                Assert.assertEquals(Match.MATCHED.toString(),
                        Objects.requireNonNull(decisions.get(BiometricType.FACE)).getMatch().toString());
                Assert.assertEquals(Match.MATCHED.toString(),
                        Objects.requireNonNull(decisions.get(BiometricType.FINGER)).getMatch().toString());
                Assert.assertEquals(Match.MATCHED.toString(),
                        Objects.requireNonNull(decisions.get(BiometricType.IRIS)).getMatch().toString());
            }
        } catch (ParserConfigurationException | SAXException | IOException e) {
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void match_noMatchingSampleAndGallery_returnsNotMatched() {
        try {
            List<BiometricType> modalitiesToMatch = new ArrayList<BiometricType>() {{
                add(BiometricType.FACE);
                add(BiometricType.FINGER);
                add(BiometricType.IRIS);
            }};
            BiometricRecord[] gallery = new BiometricRecord[1];
            BiometricRecord sampleRecord = xmlFileToBiometricRecord(testNoSampleMatchPath);
            gallery[0] = xmlFileToBiometricRecord(testNoGalleryMatchPath);

            Response<MatchDecision[]> response = new SampleSDK().match(sampleRecord, gallery, modalitiesToMatch, new HashMap<>());

            Assert.assertNotNull(response);
            Assert.assertNotNull(response.getResponse());
            for (MatchDecision decision : response.getResponse()) {
                Map<BiometricType, Decision> decisions = decision.getDecisions();
                Assert.assertEquals(Match.NOT_MATCHED.toString(),
                        Objects.requireNonNull(decisions.get(BiometricType.FINGER)).getMatch().toString());
            }
        } catch (ParserConfigurationException | SAXException | IOException e) {
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void match_lessFingersInSample_returnsMatched() {
        try {
            List<BiometricType> modalitiesToMatch = new ArrayList<BiometricType>() {{
                add(BiometricType.FACE);
                add(BiometricType.FINGER);
                add(BiometricType.IRIS);
            }};
            BiometricRecord[] gallery = new BiometricRecord[1];
            BiometricRecord sampleRecord = xmlFileToBiometricRecord(testFingerPath);
            gallery[0] = xmlFileToBiometricRecord(testMatchSDKMatchPath);

            Response<MatchDecision[]> response = new SampleSDK().match(sampleRecord, gallery, modalitiesToMatch, new HashMap<>());

            Assert.assertNotNull(response);
            Assert.assertNotNull(response.getResponse());
            for (MatchDecision decision : response.getResponse()) {
                Map<BiometricType, Decision> decisions = decision.getDecisions();
                Assert.assertEquals(Match.MATCHED.toString(),
                        Objects.requireNonNull(decisions.get(BiometricType.FACE)).getMatch().toString());
                Assert.assertEquals(Match.MATCHED.toString(),
                        Objects.requireNonNull(decisions.get(BiometricType.FINGER)).getMatch().toString());
                Assert.assertEquals(Match.MATCHED.toString(),
                        Objects.requireNonNull(decisions.get(BiometricType.IRIS)).getMatch().toString());
            }
        } catch (ParserConfigurationException | SAXException | IOException e) {
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void match_moreFingersInSample_returnsMatched() {
        try {
            List<BiometricType> modalitiesToMatch = new ArrayList<BiometricType>() {{
                add(BiometricType.FACE);
                add(BiometricType.FINGER);
                add(BiometricType.IRIS);
            }};
            BiometricRecord[] gallery = new BiometricRecord[1];
            BiometricRecord sampleRecord = xmlFileToBiometricRecord(testMoreFingersPath);
            gallery[0] = xmlFileToBiometricRecord(testMatchSDKMatchPath);

            Response<MatchDecision[]> response = new SampleSDK().match(sampleRecord, gallery, modalitiesToMatch, new HashMap<>());

            Assert.assertNotNull(response);
            Assert.assertNotNull(response.getResponse());
            for (MatchDecision decision : response.getResponse()) {
                Map<BiometricType, Decision> decisions = decision.getDecisions();
                Assert.assertEquals(Match.MATCHED.toString(),
                        Objects.requireNonNull(decisions.get(BiometricType.FACE)).getMatch().toString());
                Assert.assertEquals(Match.MATCHED.toString(),
                        Objects.requireNonNull(decisions.get(BiometricType.FINGER)).getMatch().toString());
                Assert.assertEquals(Match.MATCHED.toString(),
                        Objects.requireNonNull(decisions.get(BiometricType.IRIS)).getMatch().toString());
            }
        } catch (ParserConfigurationException | SAXException | IOException e) {
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void match_moreFingersInGallery_returnsMatched() {
        try {
            List<BiometricType> modalitiesToMatch = new ArrayList<BiometricType>() {{
                add(BiometricType.FACE);
                add(BiometricType.FINGER);
                add(BiometricType.IRIS);
            }};
            BiometricRecord[] gallery = new BiometricRecord[1];
            BiometricRecord sampleRecord = xmlFileToBiometricRecord(testMatchSDKPath);
            gallery[0] = xmlFileToBiometricRecord(testMoreFingersPath);

            Response<MatchDecision[]> response = new SampleSDK().match(sampleRecord, gallery, modalitiesToMatch, new HashMap<>());

            Assert.assertNotNull(response);
            Assert.assertNotNull(response.getResponse());
            for (MatchDecision decision : response.getResponse()) {
                Map<BiometricType, Decision> decisions = decision.getDecisions();
                Assert.assertEquals(Match.MATCHED.toString(),
                        Objects.requireNonNull(decisions.get(BiometricType.FACE)).getMatch().toString());
                Assert.assertEquals(Match.MATCHED.toString(),
                        Objects.requireNonNull(decisions.get(BiometricType.FINGER)).getMatch().toString());
                Assert.assertEquals(Match.MATCHED.toString(),
                        Objects.requireNonNull(decisions.get(BiometricType.IRIS)).getMatch().toString());
            }
        } catch (ParserConfigurationException | SAXException | IOException e) {
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void match_lessFingersInGallery_returnsMatched() {
        try {
            List<BiometricType> modalitiesToMatch = new ArrayList<BiometricType>() {{
                add(BiometricType.FACE);
                add(BiometricType.FINGER);
                add(BiometricType.IRIS);
            }};
            BiometricRecord[] gallery = new BiometricRecord[1];
            BiometricRecord sampleRecord = xmlFileToBiometricRecord(testMatchSDKPath);
            gallery[0] = xmlFileToBiometricRecord(testFingerPath);

            Response<MatchDecision[]> response = new SampleSDK().match(sampleRecord, gallery, modalitiesToMatch, new HashMap<>());

            Assert.assertNotNull(response);
            Assert.assertNotNull(response.getResponse());
            for (MatchDecision decision : response.getResponse()) {
                Map<BiometricType, Decision> decisions = decision.getDecisions();
                Assert.assertEquals(Match.MATCHED.toString(),
                        Objects.requireNonNull(decisions.get(BiometricType.FACE)).getMatch().toString());
                Assert.assertEquals(Match.MATCHED.toString(),
                        Objects.requireNonNull(decisions.get(BiometricType.FINGER)).getMatch().toString());
                Assert.assertEquals(Match.MATCHED.toString(),
                        Objects.requireNonNull(decisions.get(BiometricType.IRIS)).getMatch().toString());
            }
        } catch (ParserConfigurationException | SAXException | IOException e) {
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void match_sameFingerBiometrics_returnsMatched() {
        try {
            List<BiometricType> modalitiesToMatch = new ArrayList<BiometricType>() {{
                add(BiometricType.FINGER);
            }};
            BiometricRecord[] gallery = new BiometricRecord[1];
            BiometricRecord sampleRecord = xmlFileToBiometricRecord(testMatchSDKPath);
            gallery[0] = xmlFileToBiometricRecord(testMatchSDKMatchPath);

            Response<MatchDecision[]> response = new SampleSDK().match(sampleRecord, gallery, modalitiesToMatch, new HashMap<>());

            Assert.assertNotNull(response);
            Assert.assertNotNull(response.getResponse());
            for (MatchDecision decision : response.getResponse()) {
                Map<BiometricType, Decision> decisions = decision.getDecisions();
                Assert.assertEquals(Match.MATCHED.toString(),
                        Objects.requireNonNull(decisions.get(BiometricType.FINGER)).getMatch().toString());
            }
        } catch (ParserConfigurationException | SAXException | IOException e) {
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void match_differentFingerBiometrics_returnsMatched() {
        try {
            List<BiometricType> modalitiesToMatch = new ArrayList<BiometricType>() {{
                add(BiometricType.FINGER);
            }};
            BiometricRecord[] gallery = new BiometricRecord[1];
            BiometricRecord sampleRecord = xmlFileToBiometricRecord(testMatchSDKPath);
            gallery[0] = xmlFileToBiometricRecord(testFingerNoMatchPath);

            Response<MatchDecision[]> response = new SampleSDK().match(sampleRecord, gallery, modalitiesToMatch, new HashMap<>());

            Assert.assertNotNull(response);
            Assert.assertNotNull(response.getResponse());
            for (MatchDecision decision : response.getResponse()) {
                Map<BiometricType, Decision> decisions = decision.getDecisions();
                Assert.assertEquals(Match.MATCHED.toString(),
                        Objects.requireNonNull(decisions.get(BiometricType.FINGER)).getMatch().toString());
            }
        } catch (ParserConfigurationException | SAXException | IOException e) {
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void match_sameFaceBiometrics_returnsMatched() {
        try {
            List<BiometricType> modalitiesToMatch = new ArrayList<BiometricType>() {{
                add(BiometricType.FACE);
            }};
            BiometricRecord[] gallery = new BiometricRecord[1];
            BiometricRecord sampleRecord = xmlFileToBiometricRecord(testMatchSDKPath);
            gallery[0] = xmlFileToBiometricRecord(testMatchSDKMatchPath);

            Response<MatchDecision[]> response = new SampleSDK().match(sampleRecord, gallery, modalitiesToMatch, new HashMap<>());

            Assert.assertNotNull(response);
            Assert.assertNotNull(response.getResponse());
            for (MatchDecision decision : response.getResponse()) {
                Map<BiometricType, Decision> decisions = decision.getDecisions();
                Assert.assertEquals(Match.MATCHED.toString(),
                        Objects.requireNonNull(decisions.get(BiometricType.FACE)).getMatch().toString());
            }
        } catch (ParserConfigurationException | SAXException | IOException e) {
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void match_differentFaceBiometrics_returnsNotMatched() {
        try {
            List<BiometricType> modalitiesToMatch = new ArrayList<BiometricType>() {{
                add(BiometricType.FACE);
            }};
            BiometricRecord[] gallery = new BiometricRecord[1];
            BiometricRecord sampleRecord = xmlFileToBiometricRecord(testMatchSDKPath);
            gallery[0] = xmlFileToBiometricRecord(testFaceNoMatchPath);

            Response<MatchDecision[]> response = new SampleSDK().match(sampleRecord, gallery, modalitiesToMatch, new HashMap<>());

            Assert.assertNotNull(response);
            Assert.assertNotNull(response.getResponse());
            for (MatchDecision decision : response.getResponse()) {
                Map<BiometricType, Decision> decisions = decision.getDecisions();
                Assert.assertEquals(Match.NOT_MATCHED.toString(),
                        Objects.requireNonNull(decisions.get(BiometricType.FACE)).getMatch().toString());
            }
        } catch (ParserConfigurationException | IOException | SAXException e) {
            Assert.fail(e.getMessage());
        }
    }

    // ========== compareModality default case ==========

    @Test
    public void match_scentModality_returnsSuccessWithErrorDecision() {
        BiometricRecord sample = new BiometricRecord();
        sample.setSegments(Collections.singletonList(buildBIR(BiometricType.SCENT, "test", new byte[]{1, 2, 3})));

        BiometricRecord gallery = new BiometricRecord();
        gallery.setSegments(Collections.singletonList(buildBIR(BiometricType.SCENT, "test", new byte[]{1, 2, 3})));

        Response<MatchDecision[]> response = new SampleSDK().match(
                sample, new BiometricRecord[]{gallery},
                Collections.singletonList(BiometricType.SCENT), new HashMap<>());

        Assert.assertNotNull(response);
        Assert.assertEquals(200, (int) response.getStatusCode());
        MatchDecision[] decisions = response.getResponse();
        Assert.assertNotNull(decisions);
        Assert.assertEquals(Match.ERROR, decisions[0].getDecisions().get(BiometricType.SCENT).getMatch());
    }

    // ========== null-gallery paths (gallerySegments == null) ==========

    @Test
    public void match_fingerSampleVsIrisOnlyGallery_returnsNotMatchedForFinger() {
        try {
            BiometricRecord sample = xmlFileToBiometricRecord(testMatchSDKPath);

            BiometricRecord galleryNoFinger = new BiometricRecord();
            galleryNoFinger.setSegments(Collections.singletonList(
                    buildBIR(BiometricType.IRIS, "Left", new byte[]{1})));

            Response<MatchDecision[]> response = new SampleSDK().match(
                    sample, new BiometricRecord[]{galleryNoFinger},
                    Collections.singletonList(BiometricType.FINGER), new HashMap<>());

            Assert.assertNotNull(response);
            Assert.assertEquals(200, (int) response.getStatusCode());
            MatchDecision[] decisions = response.getResponse();
            Assert.assertNotNull(decisions);
            Assert.assertEquals(Match.NOT_MATCHED, decisions[0].getDecisions().get(BiometricType.FINGER).getMatch());
        } catch (ParserConfigurationException | IOException | SAXException e) {
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void match_irisSampleVsFingerOnlyGallery_returnsNotMatchedForIris() {
        try {
            BiometricRecord sample = xmlFileToBiometricRecord(testMatchSDKPath);

            BiometricRecord galleryNoIris = new BiometricRecord();
            galleryNoIris.setSegments(Collections.singletonList(
                    buildBIR(BiometricType.FINGER, "Left IndexFinger", new byte[]{1})));

            Response<MatchDecision[]> response = new SampleSDK().match(
                    sample, new BiometricRecord[]{galleryNoIris},
                    Collections.singletonList(BiometricType.IRIS), new HashMap<>());

            Assert.assertNotNull(response);
            Assert.assertEquals(200, (int) response.getStatusCode());
            MatchDecision[] decisions = response.getResponse();
            Assert.assertNotNull(decisions);
            Assert.assertEquals(Match.NOT_MATCHED, decisions[0].getDecisions().get(BiometricType.IRIS).getMatch());
        } catch (ParserConfigurationException | IOException | SAXException e) {
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void match_faceSampleVsFingerOnlyGallery_returnsNotMatchedForFace() {
        try {
            BiometricRecord sample = xmlFileToBiometricRecord(testMatchSDKPath);

            BiometricRecord galleryNoFace = new BiometricRecord();
            galleryNoFace.setSegments(Collections.singletonList(
                    buildBIR(BiometricType.FINGER, "Left IndexFinger", new byte[]{1})));

            Response<MatchDecision[]> response = new SampleSDK().match(
                    sample, new BiometricRecord[]{galleryNoFace},
                    Collections.singletonList(BiometricType.FACE), new HashMap<>());

            Assert.assertNotNull(response);
            Assert.assertEquals(200, (int) response.getStatusCode());
            MatchDecision[] decisions = response.getResponse();
            Assert.assertNotNull(decisions);
            Assert.assertEquals(Match.NOT_MATCHED, decisions[0].getDecisions().get(BiometricType.FACE).getMatch());
        } catch (ParserConfigurationException | IOException | SAXException e) {
            Assert.fail(e.getMessage());
        }
    }

    // ========== !bio_found paths (named subtype with no matching gallery entry) ==========

    @Test
    public void match_fingerSubtypeMismatch_coversNotFoundBranch() {
        try {
            byte[] fingerBdb = extractFirstBdb(testMatchSDKPath, BiometricType.FINGER);
            Assert.assertNotNull("Need a FINGER segment in test_sdk.xml", fingerBdb);

            // Sample: "Left IndexFinger" (named, non-UNKNOWN) → enters named-subtype loop
            BiometricRecord sample = buildSingleBirRecord(BiometricType.FINGER, "Left IndexFinger", fingerBdb);
            // Gallery: "Right Thumb" → no matching subtype → !bio_found → NOT_MATCHED
            BiometricRecord gallery = buildSingleBirRecord(BiometricType.FINGER, "Right Thumb", new byte[]{1, 2, 3});

            Response<MatchDecision[]> response = new SampleSDK().match(
                    sample, new BiometricRecord[]{gallery},
                    Collections.singletonList(BiometricType.FINGER), new HashMap<>());

            Assert.assertNotNull(response);
            Assert.assertEquals(200, (int) response.getStatusCode());
            if (response.getResponse() != null) {
                Assert.assertEquals(Match.NOT_MATCHED,
                        response.getResponse()[0].getDecisions().get(BiometricType.FINGER).getMatch());
            }
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void match_irisSubtypeMismatch_coversNotFoundBranch() {
        try {
            byte[] irisBdb = extractFirstBdb(testMatchSDKPath, BiometricType.IRIS);
            Assert.assertNotNull("Need an IRIS segment in test_sdk.xml", irisBdb);

            // Sample: "Left" iris (named, non-UNKNOWN) → enters named-subtype loop
            BiometricRecord sample = buildSingleBirRecord(BiometricType.IRIS, "Left", irisBdb);
            // Gallery: "Right" iris → "Right".equals("Left") is false → !bio_found → NOT_MATCHED
            BiometricRecord gallery = buildSingleBirRecord(BiometricType.IRIS, "Right", new byte[]{1, 2, 3});

            Response<MatchDecision[]> response = new SampleSDK().match(
                    sample, new BiometricRecord[]{gallery},
                    Collections.singletonList(BiometricType.IRIS), new HashMap<>());

            Assert.assertNotNull(response);
            Assert.assertEquals(200, (int) response.getStatusCode());
            if (response.getResponse() != null) {
                Assert.assertEquals(Match.NOT_MATCHED,
                        response.getResponse()[0].getDecisions().get(BiometricType.IRIS).getMatch());
            }
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }
    }

    // ========== NPE catch in doMatch ==========

    @Test
    public void match_galleryFingerWithNullSubtypeElement_returnsNotMatched() {
        try {
            byte[] fingerBdb = extractFirstBdb(testMatchSDKPath, BiometricType.FINGER);
            Assert.assertNotNull("Need a FINGER segment in test_sdk.xml", fingerBdb);

            // Sample: named subtype → enters the named-subtype gallery loop
            BiometricRecord sample = buildSingleBirRecord(BiometricType.FINGER, "Left IndexFinger", fingerBdb);

            // Gallery: subtype list has a null element → null guard skips segment → bio_found=false → NOT_MATCHED
            BIR.BIRBuilder galleryBuilder = new BIR.BIRBuilder();
            galleryBuilder.withVersion(new VersionType(1, 1));
            galleryBuilder.withCbeffversion(new VersionType(1, 1));
            BDBInfo.BDBInfoBuilder galleryBdbInfo = new BDBInfo.BDBInfoBuilder();
            galleryBdbInfo.withType(Collections.singletonList(BiometricType.FINGER));
            galleryBdbInfo.withSubtype(Collections.singletonList((String) null));
            galleryBuilder.withBdbInfo(new BDBInfo(galleryBdbInfo));
            galleryBuilder.withBdb(new byte[]{1, 2, 3});
            BIR galleryBir = new BIR(galleryBuilder);

            BiometricRecord gallery = new BiometricRecord();
            gallery.setSegments(Collections.singletonList(galleryBir));

            Response<MatchDecision[]> response = new SampleSDK().match(
                    sample, new BiometricRecord[]{gallery},
                    Collections.singletonList(BiometricType.FINGER), new HashMap<>());

            Assert.assertNotNull(response);
            Assert.assertEquals(200, (int) response.getStatusCode());
            MatchDecision[] decisions = response.getResponse();
            Assert.assertNotNull(decisions);
            Assert.assertEquals(Match.NOT_MATCHED, decisions[0].getDecisions().get(BiometricType.FINGER).getMatch());
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }
    }

    // ========== UNKNOWN subtype comparison paths ==========

    @Test
    public void match_fingerUnknownSubtypeSameData_returnsMatched() {
        try {
            byte[] fingerBdb = extractFirstBdb(testMatchSDKPath, BiometricType.FINGER);
            Assert.assertNotNull("Need a FINGER segment in " + testMatchSDKPath, fingerBdb);

            BiometricRecord sample = buildSingleBirRecord(BiometricType.FINGER, "UNKNOWN", fingerBdb);
            BiometricRecord gallery = buildSingleBirRecord(BiometricType.FINGER, "UNKNOWN", fingerBdb);

            Response<MatchDecision[]> response = new SampleSDK().match(
                    sample, new BiometricRecord[]{gallery},
                    Collections.singletonList(BiometricType.FINGER), new HashMap<>());

            Assert.assertNotNull(response);
            Assert.assertEquals(200, (int) response.getStatusCode());
            MatchDecision[] decisions = response.getResponse();
            Assert.assertNotNull(decisions);
            Assert.assertEquals(Match.MATCHED, decisions[0].getDecisions().get(BiometricType.FINGER).getMatch());
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void match_fingerUnknownSubtypeDifferentData_returnsNotMatched() {
        try {
            byte[] fingerBdb = extractFirstBdb(testMatchSDKPath, BiometricType.FINGER);
            Assert.assertNotNull("Need a FINGER segment in " + testMatchSDKPath, fingerBdb);

            BiometricRecord sample = buildSingleBirRecord(BiometricType.FINGER, "UNKNOWN", fingerBdb);
            BiometricRecord gallery = buildSingleBirRecord(BiometricType.FINGER, "UNKNOWN", new byte[]{9, 8, 7});

            Response<MatchDecision[]> response = new SampleSDK().match(
                    sample, new BiometricRecord[]{gallery},
                    Collections.singletonList(BiometricType.FINGER), new HashMap<>());

            Assert.assertNotNull(response);
            Assert.assertEquals(200, (int) response.getStatusCode());
            MatchDecision[] decisions = response.getResponse();
            Assert.assertNotNull(decisions);
            Assert.assertEquals(Match.NOT_MATCHED, decisions[0].getDecisions().get(BiometricType.FINGER).getMatch());
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void match_irisUnknownSubtypeSameData_returnsMatched() {
        try {
            byte[] irisBdb = extractFirstBdb(testMatchSDKPath, BiometricType.IRIS);
            Assert.assertNotNull("Need an IRIS segment in " + testMatchSDKPath, irisBdb);

            BiometricRecord sample = buildSingleBirRecord(BiometricType.IRIS, "UNKNOWN", irisBdb);
            BiometricRecord gallery = buildSingleBirRecord(BiometricType.IRIS, "UNKNOWN", irisBdb);

            Response<MatchDecision[]> response = new SampleSDK().match(
                    sample, new BiometricRecord[]{gallery},
                    Collections.singletonList(BiometricType.IRIS), new HashMap<>());

            Assert.assertNotNull(response);
            Assert.assertEquals(200, (int) response.getStatusCode());
            MatchDecision[] decisions = response.getResponse();
            Assert.assertNotNull(decisions);
            Assert.assertEquals(Match.MATCHED, decisions[0].getDecisions().get(BiometricType.IRIS).getMatch());
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void match_irisUnknownSubtypeDifferentData_returnsNotMatched() {
        try {
            byte[] irisBdb = extractFirstBdb(testMatchSDKPath, BiometricType.IRIS);
            Assert.assertNotNull("Need an IRIS segment in " + testMatchSDKPath, irisBdb);

            BiometricRecord sample = buildSingleBirRecord(BiometricType.IRIS, "UNKNOWN", irisBdb);
            BiometricRecord gallery = buildSingleBirRecord(BiometricType.IRIS, "UNKNOWN", new byte[]{9, 8, 7});

            Response<MatchDecision[]> response = new SampleSDK().match(
                    sample, new BiometricRecord[]{gallery},
                    Collections.singletonList(BiometricType.IRIS), new HashMap<>());

            Assert.assertNotNull(response);
            Assert.assertEquals(200, (int) response.getStatusCode());
            MatchDecision[] decisions = response.getResponse();
            Assert.assertNotNull(decisions);
            Assert.assertEquals(Match.NOT_MATCHED, decisions[0].getDecisions().get(BiometricType.IRIS).getMatch());
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }
    }

    // ========== getMatchDecisionInfo SDKException switch cases ==========

    // Sample with invalid finger subtype → isValidBIRParams throws MISSING_INPUT SDKException
    // → propagates through compareFingerprints/compareModality/doMatch (not caught by the narrow
    //   NullPointerException catch) → caught by getMatchDecisionInfo catch(SDKException) →
    //   MISSING_INPUT switch case covered
    @Test
    public void match_sampleWithInvalidSubtype_coversMissingInputSwitchCase() {
        BiometricRecord sample = buildSingleBirRecord(BiometricType.FINGER, "BadSubtype", new byte[]{1, 2, 3});
        BiometricRecord gallery = buildSingleBirRecord(BiometricType.FINGER, "Right Thumb", new byte[]{1, 2, 3});

        Response<MatchDecision[]> response = new SampleSDK().match(
                sample, new BiometricRecord[]{gallery},
                Collections.singletonList(BiometricType.FINGER), new HashMap<>());

        Assert.assertNotNull(response);
        Assert.assertEquals(ResponseStatus.MISSING_INPUT.getStatusCode(), (int) response.getStatusCode());
    }

    // Sample with valid subtype but invalid ISO BDB (all-zeros 200 bytes) → isValidFingerBdb
    // throws INVALID_INPUT → propagates up → INVALID_INPUT switch case covered
    @Test
    public void match_sampleWithInvalidBdb_coversInvalidInputSwitchCase() {
        byte[] invalidBdb = new byte[200]; // all-zeros: format identifier 0x00000000 ≠ "FIR\0"
        BiometricRecord sample = buildSingleBirRecord(BiometricType.FINGER, "Left IndexFinger", invalidBdb);
        BiometricRecord gallery = buildSingleBirRecord(BiometricType.FINGER, "Left IndexFinger", invalidBdb);

        Response<MatchDecision[]> response = new SampleSDK().match(
                sample, new BiometricRecord[]{gallery},
                Collections.singletonList(BiometricType.FINGER), new HashMap<>());

        Assert.assertNotNull(response);
        Assert.assertEquals(ResponseStatus.INVALID_INPUT.getStatusCode(), (int) response.getStatusCode());
    }

    // ========== Helpers ==========

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

    private BiometricRecord buildSingleBirRecord(BiometricType type, String subtype, byte[] bdb) {
        BiometricRecord record = new BiometricRecord();
        record.setSegments(Collections.singletonList(buildBIR(type, subtype, bdb)));
        return record;
    }

    private byte[] extractFirstBdb(String xmlPath, BiometricType targetType)
            throws ParserConfigurationException, IOException, SAXException {
        BiometricRecord record = xmlFileToBiometricRecord(xmlPath);
        for (BIR bir : record.getSegments()) {
            if (bir.getBdbInfo().getType().get(0) == targetType) {
                return bir.getBdb();
            }
        }
        return null;
    }

    private BiometricRecord xmlFileToBiometricRecord(String path) throws ParserConfigurationException, IOException, SAXException {
        BiometricRecord biometricRecord = new BiometricRecord();
        List<BIR> birSegments = new ArrayList<>();
        DocumentBuilder dBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        Document doc = dBuilder.parse(new File(path));
        doc.getDocumentElement().normalize();
        LOGGER.debug("Root element: {}", doc.getDocumentElement().getNodeName());
        NodeList childNodes = doc.getDocumentElement().getChildNodes();
        for (int i = 0; i < childNodes.getLength(); i++) {
            Node childNode = childNodes.item(i);
            if (!childNode.getNodeName().equalsIgnoreCase("bir")) continue;

            BIR.BIRBuilder bd = new BIR.BIRBuilder();

            Node nVersion = ((Element) childNode).getElementsByTagName("Version").item(0);
            bd.withVersion(new VersionType(
                    parseInt(((Element) nVersion).getElementsByTagName("Major").item(0).getTextContent()),
                    parseInt(((Element) nVersion).getElementsByTagName("Minor").item(0).getTextContent())));
            bd.withCbeffversion(new VersionType(
                    parseInt(((Element) nVersion).getElementsByTagName("Major").item(0).getTextContent()),
                    parseInt(((Element) nVersion).getElementsByTagName("Minor").item(0).getTextContent())));

            Node nBDBInfo = ((Element) childNode).getElementsByTagName("BDBInfo").item(0);
            String bdbInfoType = "";
            String bdbInfoSubtype = "";
            QualityType quality = null;
            NodeList bdbInfoChildren = nBDBInfo.getChildNodes();
            for (int z = 0; z < bdbInfoChildren.getLength(); z++) {
                Node child = bdbInfoChildren.item(z);
                if (child.getNodeName().equalsIgnoreCase("Type")) {
                    bdbInfoType = child.getTextContent();
                } else if (child.getNodeName().equalsIgnoreCase("Subtype")) {
                    bdbInfoSubtype = child.getTextContent();
                } else if (child.getNodeName().equalsIgnoreCase("Quality")) {
                    NodeList qualityChildren = child.getChildNodes();
                    for (int q = 0; q < qualityChildren.getLength(); q++) {
                        Node qChild = qualityChildren.item(q);
                        if (qChild.getNodeName().equalsIgnoreCase("Score")) {
                            quality = new QualityType();
                            quality.setScore(Long.parseLong(qChild.getTextContent().trim()));
                        }
                    }
                }
            }

            BDBInfo.BDBInfoBuilder bdbInfoBuilder = new BDBInfo.BDBInfoBuilder();
            bdbInfoBuilder.withType(Collections.singletonList(BiometricType.fromValue(bdbInfoType)));
            bdbInfoBuilder.withSubtype(Collections.singletonList(bdbInfoSubtype));
            if (quality != null) {
                bdbInfoBuilder.withQuality(quality);
            }
            bd.withBdbInfo(new BDBInfo(bdbInfoBuilder));
            bd.withBdb(Util.decodeURLSafeBase64(((Element) childNode).getElementsByTagName("BDB").item(0).getTextContent()));

            birSegments.add(new BIR(bd));
        }
        biometricRecord.setSegments(birSegments);
        return biometricRecord;
    }
}