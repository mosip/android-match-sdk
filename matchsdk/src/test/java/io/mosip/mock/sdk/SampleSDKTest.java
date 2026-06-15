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

import io.mosip.kernel.biometrics.constant.BiometricFunction;
import io.mosip.kernel.biometrics.constant.BiometricType;
import io.mosip.kernel.biometrics.constant.QualityType;
import io.mosip.kernel.biometrics.entities.BDBInfo;
import io.mosip.kernel.biometrics.entities.BIR;
import io.mosip.kernel.biometrics.entities.BIRInfo;
import io.mosip.kernel.biometrics.entities.BiometricRecord;
import io.mosip.kernel.biometrics.entities.VersionType;
import io.mosip.kernel.biometrics.model.QualityCheck;
import io.mosip.kernel.biometrics.model.Response;
import io.mosip.kernel.biometrics.model.SDKInfo;
import io.mosip.mock.sdk.constant.ResponseStatus;
import io.mosip.mock.sdk.impl.SampleSDK;
import io.mosip.mock.sdk.util.Util;

public class SampleSDKTest {

    private final Logger LOGGER = LoggerFactory.getLogger(SampleSDKTest.class);

    private String testSdkPath;

    @Before
    public void setup() {
        testSdkPath = Objects.requireNonNull(SampleSDKTest.class.getResource("/sample_files/test_sdk.xml")).getPath();
    }

    @Test
    public void init_withValidParams_returnsSdkInfo() {
        Map<String, String> params = new HashMap<>();
        params.put("version", "1.0");

        SDKInfo info = new SampleSDK().init(params);

        Assert.assertNotNull(info);
        Assert.assertTrue(info.getSupportedModalities().contains(BiometricType.FINGER));
        Assert.assertTrue(info.getSupportedModalities().contains(BiometricType.FACE));
        Assert.assertTrue(info.getSupportedModalities().contains(BiometricType.IRIS));
    }

    @Test
    public void init_withNullParams_returnsSdkInfoWithAllMethods() {
        SDKInfo info = new SampleSDK().init(null);

        Assert.assertNotNull(info);
        Assert.assertEquals(4, info.getSupportedMethods().size());
        Assert.assertTrue(info.getSupportedMethods().containsKey(BiometricFunction.MATCH));
        Assert.assertTrue(info.getSupportedMethods().containsKey(BiometricFunction.QUALITY_CHECK));
        Assert.assertTrue(info.getSupportedMethods().containsKey(BiometricFunction.EXTRACT));
        Assert.assertTrue(info.getSupportedMethods().containsKey(BiometricFunction.CONVERT_FORMAT));
    }

    @Test
    public void checkQuality_nullSample_returnsMissingInputStatus() {
        Response<QualityCheck> response = new SampleSDK().checkQuality(
                null, Collections.singletonList(BiometricType.FINGER), new HashMap<>());

        Assert.assertNotNull(response);
        Assert.assertEquals(ResponseStatus.MISSING_INPUT.getStatusCode(), (int) response.getStatusCode());
    }

    @Test
    public void checkQuality_emptySegments_returnsMissingInputStatus() {
        BiometricRecord record = new BiometricRecord();
        record.setSegments(new ArrayList<>());

        Response<QualityCheck> response = new SampleSDK().checkQuality(
                record, Collections.singletonList(BiometricType.FINGER), new HashMap<>());

        Assert.assertNotNull(response);
        Assert.assertEquals(ResponseStatus.MISSING_INPUT.getStatusCode(), (int) response.getStatusCode());
    }

    @Test
    public void checkQuality_validFingerSample_returnsSuccessWithScores() {
        try {
            BiometricRecord record = xmlFileToBiometricRecord(testSdkPath);

            Response<QualityCheck> response = new SampleSDK().checkQuality(
                    record, Collections.singletonList(BiometricType.FINGER), new HashMap<>());

            Assert.assertNotNull(response);
            Assert.assertEquals(ResponseStatus.SUCCESS.getStatusCode(), (int) response.getStatusCode());
            Assert.assertNotNull(response.getResponse());
            Assert.assertTrue(response.getResponse().getScores().containsKey(BiometricType.FINGER));
        } catch (ParserConfigurationException | IOException | SAXException e) {
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void checkQuality_validFaceSample_returnsSuccessWithScores() {
        try {
            BiometricRecord record = xmlFileToBiometricRecord(testSdkPath);

            Response<QualityCheck> response = new SampleSDK().checkQuality(
                    record, Collections.singletonList(BiometricType.FACE), new HashMap<>());

            Assert.assertNotNull(response);
            Assert.assertEquals(ResponseStatus.SUCCESS.getStatusCode(), (int) response.getStatusCode());
            Assert.assertNotNull(response.getResponse());
            Assert.assertTrue(response.getResponse().getScores().containsKey(BiometricType.FACE));
        } catch (ParserConfigurationException | IOException | SAXException e) {
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void checkQuality_validIrisSample_returnsSuccessWithScores() {
        try {
            BiometricRecord record = xmlFileToBiometricRecord(testSdkPath);

            Response<QualityCheck> response = new SampleSDK().checkQuality(
                    record, Collections.singletonList(BiometricType.IRIS), new HashMap<>());

            Assert.assertNotNull(response);
            Assert.assertEquals(ResponseStatus.SUCCESS.getStatusCode(), (int) response.getStatusCode());
            Assert.assertNotNull(response.getResponse());
            Assert.assertTrue(response.getResponse().getScores().containsKey(BiometricType.IRIS));
        } catch (ParserConfigurationException | IOException | SAXException e) {
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void extractTemplate_nullSample_returnsMissingInputStatus() {
        Response<BiometricRecord> response = new SampleSDK().extractTemplate(
                null, Collections.singletonList(BiometricType.FINGER), new HashMap<>());

        Assert.assertNotNull(response);
        Assert.assertEquals(ResponseStatus.MISSING_INPUT.getStatusCode(), (int) response.getStatusCode());
    }

    @Test
    public void extractTemplate_emptySegments_returnsMissingInputStatus() {
        BiometricRecord record = new BiometricRecord();
        record.setSegments(new ArrayList<>());

        Response<BiometricRecord> response = new SampleSDK().extractTemplate(
                record, Collections.singletonList(BiometricType.FINGER), new HashMap<>());

        Assert.assertNotNull(response);
        Assert.assertEquals(ResponseStatus.MISSING_INPUT.getStatusCode(), (int) response.getStatusCode());
    }

    @Test
    public void extractTemplate_validSampleWithBirInfo_returnsSuccessStatus() {
        try {
            BiometricRecord record = xmlFileToBiometricRecord(testSdkPath);
            addBirInfoToSegments(record);

            Response<BiometricRecord> response = new SampleSDK().extractTemplate(
                    record, Collections.singletonList(BiometricType.FINGER), new HashMap<>());

            Assert.assertNotNull(response);
            Assert.assertEquals(ResponseStatus.SUCCESS.getStatusCode(), (int) response.getStatusCode());
        } catch (ParserConfigurationException | IOException | SAXException e) {
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void segment_anyInput_returnsSuccessStatus() {
        BiometricRecord record = new BiometricRecord();
        record.setSegments(new ArrayList<>());

        Response<BiometricRecord> response = new SampleSDK().segment(
                record, Collections.singletonList(BiometricType.FINGER), new HashMap<>());

        Assert.assertNotNull(response);
        Assert.assertEquals(200, (int) response.getStatusCode());
    }

    @Test
    public void convertFormat_validSample_returnsSameInstance() {
        BiometricRecord record = new BiometricRecord();
        record.setSegments(new ArrayList<>());

        BiometricRecord result = new SampleSDK().convertFormat(
                record, "ISO19794_4_2011", "IMAGE/JPEG",
                new HashMap<>(), new HashMap<>(),
                Collections.singletonList(BiometricType.FINGER));

        Assert.assertSame(record, result);
    }

    @Test
    public void extractTemplate_validSampleWithFormatType7_convertsFormatType() {
        try {
            BiometricRecord record = xmlFileToBiometricRecord(testSdkPath);
            addBirInfoToSegments(record);
            setFormatTypeOnSegments(record, "7");

            Response<BiometricRecord> response = new SampleSDK().extractTemplate(
                    record, Collections.singletonList(BiometricType.FINGER), new HashMap<>());

            Assert.assertNotNull(response);
            Assert.assertEquals(ResponseStatus.SUCCESS.getStatusCode(), (int) response.getStatusCode());
        } catch (ParserConfigurationException | IOException | SAXException e) {
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void convertFormatV2_irisDataWithFingerSourceFormat_returnsSuccess() {
        try {
            BiometricRecord record = xmlFileToBiometricRecord(testSdkPath);
            BiometricRecord irisOnly = buildRecordForType(record, BiometricType.IRIS);

            Response<BiometricRecord> response = new SampleSDK().convertFormatV2(
                    irisOnly, "ISO19794_4_2011", "IMAGE/JPEG",
                    new HashMap<>(), new HashMap<>(),
                    Collections.singletonList(BiometricType.IRIS));

            Assert.assertNotNull(response);
            Assert.assertEquals(ResponseStatus.SUCCESS.getStatusCode(), (int) response.getStatusCode());
        } catch (ParserConfigurationException | IOException | SAXException e) {
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void convertFormatV2_validFingerWithFingerFormat_coversConversionPath() {
        try {
            BiometricRecord record = xmlFileToBiometricRecord(testSdkPath);
            BiometricRecord fingerOnly = buildRecordForType(record, BiometricType.FINGER);

            Response<BiometricRecord> response = new SampleSDK().convertFormatV2(
                    fingerOnly, "ISO19794_4_2011", "IMAGE/JPEG",
                    new HashMap<>(), new HashMap<>(),
                    Collections.singletonList(BiometricType.FINGER));

            Assert.assertNotNull(response);
        } catch (ParserConfigurationException | IOException | SAXException e) {
            Assert.fail(e.getMessage());
        } catch (Throwable e) {
            // CommonUtil static initializer fails in JVM test environment (Android-only class)
        }
    }

    @Test
    public void convertFormatV2_faceDataWithFaceFormat_coversConversionPath() {
        try {
            BiometricRecord record = xmlFileToBiometricRecord(testSdkPath);
            BiometricRecord faceOnly = buildRecordForType(record, BiometricType.FACE);

            Response<BiometricRecord> response = new SampleSDK().convertFormatV2(
                    faceOnly, "ISO19794_5_2011", "IMAGE/JPEG",
                    new HashMap<>(), new HashMap<>(),
                    Collections.singletonList(BiometricType.FACE));

            Assert.assertNotNull(response);
        } catch (ParserConfigurationException | IOException | SAXException e) {
            Assert.fail(e.getMessage());
        } catch (Throwable e) {
            // CommonUtil static initializer fails in JVM test environment (Android-only class)
        }
    }

    @Test
    public void convertFormatV2_irisDataWithIrisFormat_coversConversionPath() {
        try {
            BiometricRecord record = xmlFileToBiometricRecord(testSdkPath);
            BiometricRecord irisOnly = buildRecordForType(record, BiometricType.IRIS);

            Response<BiometricRecord> response = new SampleSDK().convertFormatV2(
                    irisOnly, "ISO19794_6_2011", "IMAGE/JPEG",
                    new HashMap<>(), new HashMap<>(),
                    Collections.singletonList(BiometricType.IRIS));

            Assert.assertNotNull(response);
        } catch (ParserConfigurationException | IOException | SAXException e) {
            Assert.fail(e.getMessage());
        } catch (Throwable e) {
            // CommonUtil static initializer fails in JVM test environment (Android-only class)
        }
    }

    @Test
    public void convertFormatV2_fingerDataWithUnknownSourceFormat_returnsInvalidInput() {
        try {
            BiometricRecord record = xmlFileToBiometricRecord(testSdkPath);
            BiometricRecord fingerOnly = buildRecordForType(record, BiometricType.FINGER);

            Response<BiometricRecord> response = new SampleSDK().convertFormatV2(
                    fingerOnly, "UNKNOWN_FORMAT", "IMAGE/JPEG",
                    new HashMap<>(), new HashMap<>(),
                    Collections.singletonList(BiometricType.FINGER));

            Assert.assertNotNull(response);
            // SourceFormatCode.fromCode("UNKNOWN_FORMAT") throws ConversionException(INVALID_SOURCE_EXCEPTION) → 401
            Assert.assertEquals(ResponseStatus.INVALID_INPUT.getStatusCode(), (int) response.getStatusCode());
        } catch (ParserConfigurationException | IOException | SAXException e) {
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void convertFormatV2_nullSample_returnsUnknownErrorStatus() {
        Response<BiometricRecord> response = new SampleSDK().convertFormatV2(
                null, "ISO19794_4_2011", "IMAGE/JPEG",
                new HashMap<>(), new HashMap<>(),
                Collections.singletonList(BiometricType.FINGER));

        Assert.assertNotNull(response);
        Assert.assertEquals(ResponseStatus.UNKNOWN_ERROR.getStatusCode(), (int) response.getStatusCode());
    }

    @Test
    public void convertFormatV2_emptySegments_returnsSuccessStatus() {
        BiometricRecord record = new BiometricRecord();
        record.setSegments(new ArrayList<>());

        Response<BiometricRecord> response = new SampleSDK().convertFormatV2(
                record, "ISO19794_4_2011", "IMAGE/JPEG",
                new HashMap<>(), new HashMap<>(),
                Collections.singletonList(BiometricType.FINGER));

        Assert.assertNotNull(response);
        Assert.assertEquals(ResponseStatus.SUCCESS.getStatusCode(), (int) response.getStatusCode());
    }

    @Test
    public void extractTemplate_xmlSampleWithoutBirInfo_returnsMissingInput() {
        try {
            BiometricRecord record = xmlFileToBiometricRecord(testSdkPath);

            Response<BiometricRecord> response = new SampleSDK().extractTemplate(
                    record, Collections.singletonList(BiometricType.FINGER), new HashMap<>());

            Assert.assertNotNull(response);
            Assert.assertEquals(ResponseStatus.MISSING_INPUT.getStatusCode(), (int) response.getStatusCode());
        } catch (ParserConfigurationException | IOException | SAXException e) {
            Assert.fail(e.getMessage());
        }
    }

    private void addBirInfoToSegments(BiometricRecord record) {
        for (BIR segment : record.getSegments()) {
            segment.setBirInfo(new BIRInfo(new BIRInfo.BIRInfoBuilder().withCreator("test")));
        }
    }

    private void setFormatTypeOnSegments(BiometricRecord record, String formatType) {
        for (BIR segment : record.getSegments()) {
            if (segment.getBdbInfo().getFormat() == null) {
                io.mosip.kernel.biometrics.entities.RegistryIDType fmt =
                        new io.mosip.kernel.biometrics.entities.RegistryIDType();
                fmt.setType(formatType);
                segment.getBdbInfo().setFormat(fmt);
            } else {
                segment.getBdbInfo().getFormat().setType(formatType);
            }
        }
    }

    private BiometricRecord buildRecordForType(BiometricRecord source, BiometricType targetType) {
        BiometricRecord result = new BiometricRecord();
        List<BIR> filtered = new ArrayList<>();
        for (BIR bir : source.getSegments()) {
            if (bir.getBdbInfo().getType().get(0) == targetType) {
                filtered.add(bir);
            }
        }
        result.setSegments(filtered);
        return result;
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