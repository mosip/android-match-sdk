package io.mosip.registration.matchsdk;

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
import io.mosip.kernel.biometrics.entities.BDBInfo;
import io.mosip.kernel.biometrics.entities.BIR;
import io.mosip.kernel.biometrics.entities.BiometricRecord;
import io.mosip.kernel.biometrics.entities.VersionType;
import io.mosip.kernel.biometrics.model.Decision;
import io.mosip.kernel.biometrics.model.MatchDecision;
import io.mosip.kernel.biometrics.model.Response;
import io.mosip.registration.matchsdk.impl.MatchSDK;
import io.mosip.registration.matchsdk.util.Util;

public class MatchSDKTest {

    Logger LOGGER = LoggerFactory.getLogger(MatchSDKTest.class);

    private String testIrisNoMatchPath = "";
    private String testMatchSDKPath = "";
    private String testMatchSDKMatchPath = "";
    private String testFaceNoMatchPath = "";
    private String testFingerNoMatchPath = "";

    @Before
    public void Setup() {
        testIrisNoMatchPath = Objects.requireNonNull(MatchSDKTest.class.getResource("/sample_files/test_sdk_iris_no_match.xml")).getPath();
        testMatchSDKPath = Objects.requireNonNull(MatchSDKTest.class.getResource("/sample_files/test_sdk.xml")).getPath();
        testMatchSDKMatchPath = Objects.requireNonNull(MatchSDKTest.class.getResource("/sample_files/test_sdk_match.xml")).getPath();
        testFaceNoMatchPath = Objects.requireNonNull(MatchSDKTest.class.getResource("/sample_files/test_sdk_face_no_match.xml")).getPath();
        testFingerNoMatchPath = Objects.requireNonNull(MatchSDKTest.class.getResource("/sample_files/test_sdk_finger_no_match.xml")).getPath();
    }

    @Test
    public void match_same_iris() {
        try {
            List<BiometricType> modalitiesToMatch = new ArrayList<BiometricType>(){{
                add(BiometricType.IRIS);
            }};
            BiometricRecord[] gallery = new BiometricRecord[1];
            BiometricRecord sample_record = xmlFileToBiometricRecord(testMatchSDKPath);
            BiometricRecord gallery0 = xmlFileToBiometricRecord(testMatchSDKMatchPath);

            gallery[0] = gallery0;

            MatchSDK sampleSDK = new MatchSDK();
            Response<MatchDecision[]> response = sampleSDK.match(sample_record, gallery, modalitiesToMatch, new HashMap<>());
            if (response != null && response.getResponse() != null)
            {
                for (int i=0; i< response.getResponse().length; i++){
                    Map<BiometricType, Decision> decisions = response.getResponse()[i].getDecisions();
                    Assert.assertEquals(Objects.requireNonNull(decisions.get(BiometricType.IRIS)).toString(), Objects.requireNonNull(decisions.get(BiometricType.IRIS)).getMatch().toString(), Match.MATCHED.toString());
                }
            }
        } catch (ParserConfigurationException | IOException | SAXException e) {
            e.printStackTrace();
        }
    }
    @Test
    public void match_different_iris() {
        try {
            List<BiometricType> modalitiesToMatch = new ArrayList<BiometricType>(){{
                add(BiometricType.IRIS);
            }};
            BiometricRecord[] gallery = new BiometricRecord[1];
            BiometricRecord sample_record = xmlFileToBiometricRecord(testMatchSDKPath);
            BiometricRecord gallery0 = xmlFileToBiometricRecord(testIrisNoMatchPath);

            gallery[0] = gallery0;

            MatchSDK sampleSDK = new MatchSDK();
            Response<MatchDecision[]> response = sampleSDK.match(sample_record, gallery, modalitiesToMatch, new HashMap<>());
            if (response != null && response.getResponse() != null)
            {
                for (int i=0; i< response.getResponse().length; i++){
                    Map<BiometricType, Decision> decisions = response.getResponse()[i].getDecisions();
                    Assert.assertEquals(Objects.requireNonNull(decisions.get(BiometricType.IRIS)).toString(), Objects.requireNonNull(decisions.get(BiometricType.IRIS)).getMatch().toString(), Match.NOT_MATCHED.toString());
                }
            }
        } catch (ParserConfigurationException | IOException | SAXException e) {
            e.printStackTrace();
        }
    }
    @Test
    public void full_match() {
        try {
            List<BiometricType> modalitiesToMatch = new ArrayList<BiometricType>(){{
                add(BiometricType.FACE);
                add(BiometricType.FINGER);
                add(BiometricType.IRIS);
            }};
            BiometricRecord[] gallery = new BiometricRecord[1];
            BiometricRecord sample_record = xmlFileToBiometricRecord(testMatchSDKPath);
            BiometricRecord gallery0 = xmlFileToBiometricRecord(testMatchSDKMatchPath);

            gallery[0] = gallery0;

            MatchSDK sampleSDK = new MatchSDK();
            Response<MatchDecision[]> response = sampleSDK.match(sample_record, gallery, modalitiesToMatch, new HashMap<>());
            if (response != null && response.getResponse() != null)
            {
                for (int i=0; i< response.getResponse().length; i++){
                    Map<BiometricType, Decision> decisions = response.getResponse()[i].getDecisions();
                    Assert.assertEquals(Objects.requireNonNull(decisions.get(BiometricType.FACE)).toString(), Objects.requireNonNull(decisions.get(BiometricType.FACE)).getMatch().toString(), Match.MATCHED.toString());
                    Assert.assertEquals(Objects.requireNonNull(decisions.get(BiometricType.FINGER)).toString(), Objects.requireNonNull(decisions.get(BiometricType.FINGER)).getMatch().toString(), Match.MATCHED.toString());
                    Assert.assertEquals(Objects.requireNonNull(decisions.get(BiometricType.IRIS)).toString(), Objects.requireNonNull(decisions.get(BiometricType.IRIS)).getMatch().toString(), Match.MATCHED.toString());
                }
            }
        } catch (ParserConfigurationException | SAXException | IOException e) {
            e.printStackTrace();
        }
    }

    @Test
    public void match_same_finger() {
        try {
            List<BiometricType> modalitiesToMatch = new ArrayList<BiometricType>(){{
                add(BiometricType.FINGER);
            }};
            BiometricRecord[] gallery = new BiometricRecord[1];
            BiometricRecord sample_record = xmlFileToBiometricRecord(testMatchSDKPath);
            BiometricRecord gallery0 = xmlFileToBiometricRecord(testMatchSDKMatchPath);

            gallery[0] = gallery0;

            MatchSDK sampleSDK = new MatchSDK();
            Response<MatchDecision[]> response = sampleSDK.match(sample_record, gallery, modalitiesToMatch, new HashMap<>());
            if (response != null && response.getResponse() != null)
            {
                for (int i=0; i< response.getResponse().length; i++){
                    Map<BiometricType, Decision> decisions = response.getResponse()[i].getDecisions();
                    Assert.assertEquals(Objects.requireNonNull(decisions.get(BiometricType.FINGER)).toString(), Objects.requireNonNull(decisions.get(BiometricType.FINGER)).getMatch().toString(), Match.MATCHED.toString());
                }
            }
        } catch (ParserConfigurationException | SAXException | IOException e) {
            e.printStackTrace();
        }
    }
    @Test
    public void match_different_finger() {
        try {
            List<BiometricType> modalitiesToMatch = new ArrayList<BiometricType>(){{
                add(BiometricType.FINGER);
            }};
            BiometricRecord[] gallery = new BiometricRecord[1];
            BiometricRecord sample_record = xmlFileToBiometricRecord(testMatchSDKPath);
            BiometricRecord gallery0 = xmlFileToBiometricRecord(testFingerNoMatchPath);

            gallery[0] = gallery0;

            MatchSDK sampleSDK = new MatchSDK();
            Response<MatchDecision[]> response = sampleSDK.match(sample_record, gallery, modalitiesToMatch, new HashMap<>());
            if (response != null && response.getResponse() != null)
            {
                for (int i=0; i< response.getResponse().length; i++){
                    Map<BiometricType, Decision> decisions = response.getResponse()[i].getDecisions();
                    Assert.assertEquals(Objects.requireNonNull(decisions.get(BiometricType.FINGER)).toString(), Objects.requireNonNull(decisions.get(BiometricType.FINGER)).getMatch().toString(), Match.MATCHED.toString());
                }
            }
        } catch (ParserConfigurationException | SAXException | IOException e) {
            e.printStackTrace();
        }
    }
    @Test
    public void match_same_face() {
        try {
            List<BiometricType> modalitiesToMatch = new ArrayList<BiometricType>(){{
                add(BiometricType.FACE);
            }};
            BiometricRecord[] gallery = new BiometricRecord[1];
            BiometricRecord sample_record = xmlFileToBiometricRecord(testMatchSDKPath);
            BiometricRecord gallery0 = xmlFileToBiometricRecord(testMatchSDKMatchPath);

            gallery[0] = gallery0;

            MatchSDK sampleSDK = new MatchSDK();
            Response<MatchDecision[]> response = sampleSDK.match(sample_record, gallery, modalitiesToMatch, new HashMap<>());
            if (response != null && response.getResponse() != null)
            {
                for (int i=0; i< response.getResponse().length; i++){
                    Map<BiometricType, Decision> decisions = response.getResponse()[i].getDecisions();
                    Assert.assertEquals(Objects.requireNonNull(decisions.get(BiometricType.FACE)).toString(), Objects.requireNonNull(decisions.get(BiometricType.FACE)).getMatch().toString(), Match.MATCHED.toString());
                }
            }
        } catch (ParserConfigurationException | SAXException | IOException e) {
            e.printStackTrace();
        }
    }

    @Test
    public void match_different_face() {
        try {
            List<BiometricType> modalitiesToMatch = new ArrayList<BiometricType>(){{
                add(BiometricType.FACE);
            }};
            BiometricRecord[] gallery = new BiometricRecord[1];
            BiometricRecord sample_record = xmlFileToBiometricRecord(testMatchSDKPath);
            BiometricRecord gallery0 = xmlFileToBiometricRecord(testFaceNoMatchPath);

            gallery[0] = gallery0;

            MatchSDK sampleSDK = new MatchSDK();
            Response<MatchDecision[]> response = sampleSDK.match(sample_record, gallery, modalitiesToMatch, new HashMap<>());
            if (response != null && response.getResponse() != null)
            {
                for (int i=0; i< response.getResponse().length; i++){
                    Map<BiometricType, Decision> decisions = response.getResponse()[i].getDecisions();
                    Assert.assertEquals(Objects.requireNonNull(decisions.get(BiometricType.FACE)).toString(),
                            Objects.requireNonNull(decisions.get(BiometricType.FACE)).getMatch().toString(),
                            Match.NOT_MATCHED.toString());
                }
            }
        } catch (ParserConfigurationException | IOException | SAXException e) {
            e.printStackTrace();
        }
    }


    private BiometricRecord xmlFileToBiometricRecord(String path) throws ParserConfigurationException, IOException, SAXException {
        BiometricRecord biometricRecord = new BiometricRecord();
        List<BIR> bir_segments = new ArrayList<>();
        File fXmlFile = new File(path);
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        Document doc = dBuilder.parse(fXmlFile);
        doc.getDocumentElement().normalize();
        LOGGER.debug("Root element :" + doc.getDocumentElement().getNodeName());
        Node rootBIRElement = doc.getDocumentElement();
        NodeList childNodes = rootBIRElement.getChildNodes();
        for (int temp = 0; temp < childNodes.getLength(); temp++) {
            Node childNode = childNodes.item(temp);
            if(childNode.getNodeName().equalsIgnoreCase("bir")){
                BIR.BIRBuilder bd = new BIR.BIRBuilder();

                /* Version */
                Node nVersion = ((Element) childNode).getElementsByTagName("Version").item(0);
                String major_version = ((Element) nVersion).getElementsByTagName("Major").item(0).getTextContent();
                String minor_version = ((Element) nVersion).getElementsByTagName("Minor").item(0).getTextContent();
                VersionType bir_version = new VersionType(parseInt(major_version), parseInt(minor_version));
                bd.withVersion(bir_version);

                /* Version */
                Node nCBEFFVersion = ((Element) childNode).getElementsByTagName("Version").item(0);
                String _major_version = ((Element) nCBEFFVersion).getElementsByTagName("Major").item(0).getTextContent();
                String _minor_version = ((Element) nCBEFFVersion).getElementsByTagName("Minor").item(0).getTextContent();
                VersionType _bir_version = new VersionType(parseInt(_major_version), parseInt(_minor_version));
                bd.withCbeffversion(_bir_version);

                /* BDB Info */
                Node nBDBInfo = ((Element) childNode).getElementsByTagName("BDBInfo").item(0);
                String bdb_info_type = "";
                String bdb_info_subtype = "";
                NodeList nBDBInfoChildren = nBDBInfo.getChildNodes();
                for (int z=0; z < nBDBInfoChildren.getLength(); z++){
                    Node nBDBInfoChild = nBDBInfoChildren.item(z);
                    if(nBDBInfoChild.getNodeName().equalsIgnoreCase("Type")){
                        bdb_info_type = nBDBInfoChild.getTextContent();
                    }
                    if(nBDBInfoChild.getNodeName().equalsIgnoreCase("Subtype")){
                        bdb_info_subtype = nBDBInfoChild.getTextContent();
                    }
                }

                BDBInfo.BDBInfoBuilder bdbInfoBuilder = new BDBInfo.BDBInfoBuilder();
                bdbInfoBuilder.withType(Collections.singletonList(BiometricType.fromValue(bdb_info_type)));
                bdbInfoBuilder.withSubtype(Collections.singletonList(bdb_info_subtype));
                BDBInfo bdbInfo = new BDBInfo(bdbInfoBuilder);
                bd.withBdbInfo(bdbInfo);

                /* BDB */
                String nBDB = ((Element) childNode).getElementsByTagName("BDB").item(0).getTextContent();
                bd.withBdb(Util.decodeURLSafeBase64(nBDB));

                /* Prepare BIR */
                BIR bir = new BIR(bd);

                /* Add BIR to list of segments */
                bir_segments.add(bir);
            }
        }
        biometricRecord.setSegments(bir_segments);
        return biometricRecord;
    }
}
