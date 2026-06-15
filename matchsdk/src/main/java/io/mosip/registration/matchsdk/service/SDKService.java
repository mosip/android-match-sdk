package io.mosip.registration.matchsdk.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import io.mosip.biometrics.util.ConvertRequestDto;
import io.mosip.biometrics.util.face.FaceBDIR;
import io.mosip.biometrics.util.face.FaceDecoder;
import io.mosip.biometrics.util.face.FaceISOStandardsValidator;
import io.mosip.biometrics.util.face.FaceQualityBlock;
import io.mosip.biometrics.util.face.ImageColourSpace;
import io.mosip.biometrics.util.face.ImageDataType;
import io.mosip.biometrics.util.face.LandmarkPoints;
import io.mosip.biometrics.util.finger.FingerBDIR;
import io.mosip.biometrics.util.finger.FingerCertificationBlock;
import io.mosip.biometrics.util.finger.FingerDecoder;
import io.mosip.biometrics.util.finger.FingerISOStandardsValidator;
import io.mosip.biometrics.util.finger.FingerImageCompressionType;
import io.mosip.biometrics.util.finger.FingerPosition;
import io.mosip.biometrics.util.finger.FingerQualityBlock;
import io.mosip.biometrics.util.iris.EyeLabel;
import io.mosip.biometrics.util.iris.ImageType;
import io.mosip.biometrics.util.iris.IrisBDIR;
import io.mosip.biometrics.util.iris.IrisDecoder;
import io.mosip.biometrics.util.iris.IrisISOStandardsValidator;
import io.mosip.biometrics.util.iris.IrisImageCompressionType;
import io.mosip.biometrics.util.iris.IrisQualityBlock;
import io.mosip.kernel.biometrics.constant.BiometricType;
import io.mosip.kernel.biometrics.constant.PurposeType;
import io.mosip.kernel.biometrics.entities.BIR;
import io.mosip.kernel.biometrics.entities.BiometricRecord;
import io.mosip.registration.matchsdk.constant.ResponseStatus;
import io.mosip.registration.matchsdk.exception.SDKException;
import io.mosip.registration.matchsdk.util.Util;

public abstract class SDKService {
    protected Logger LOGGER = LoggerFactory.getLogger(SDKService.class);
    private Map<String, String> flags;

    protected SDKService(Map<String, String> flags) {
        setFlags(flags);
    }

    protected Map<String, String> getFlags() {
        return flags;
    }

    protected void setFlags(Map<String, String> flags) {
        this.flags = flags;
    }

    protected Map<BiometricType, List<BIR>> getBioSegmentMap(BiometricRecord record,
                                                             List<BiometricType> modalitiesToMatch) {
        LOGGER.info("getBioSegmentMap>>" +  modalitiesToMatch.toString());
        boolean noFilter = modalitiesToMatch.isEmpty();

        Map<BiometricType, List<BIR>> bioSegmentMap = new HashMap<>();
        for (BIR segment : record.getSegments()) {
            BiometricType bioType = segment.getBdbInfo().getType().get(0);

            // ignore modalities that are not to be matched

            if (!noFilter && !modalitiesToMatch.contains(bioType))
                continue;

            if (!bioSegmentMap.containsKey(bioType)) {
                bioSegmentMap.put(bioType, new ArrayList<BIR>());
            }
            Objects.requireNonNull(bioSegmentMap.get(bioType)).add(segment);
        }

        return bioSegmentMap;
    }

    protected boolean isValidBirData(BIR bir) {
        BiometricType biometricType = bir.getBdbInfo().getType().get(0);
        PurposeType purposeType = bir.getBdbInfo().getPurpose();
        List<String> bioSubTypeList = bir.getBdbInfo().getSubtype();

        String bioSubType = null;
        if (bioSubTypeList != null && !bioSubTypeList.isEmpty()) {
            bioSubType = bioSubTypeList.get(0).trim();
            if (bioSubTypeList.size() >= 2)
                bioSubType += " " + bioSubTypeList.get(1).trim();
        }

        if (!isValidBIRParams(bir, biometricType, bioSubType))
            return false;

        if (!isValidBDBData(purposeType, biometricType, bioSubType, bir.getBdb()))
            return false;

        return true;
    }

    protected boolean isValidBIRParams(BIR segment, BiometricType bioType, String bioSubType) {
        ResponseStatus responseStatus = null;
        switch (bioType) {
            case FACE:
                break;
            case FINGER:
                if (!(bioSubType.equals("UNKNOWN") || bioSubType.equals("Left IndexFinger")
                        || bioSubType.equals("Left RingFinger") || bioSubType.equals("Left MiddleFinger")
                        || bioSubType.equals("Left LittleFinger") || bioSubType.equals("Left Thumb")
                        || bioSubType.equals("Right IndexFinger") || bioSubType.equals("Right RingFinger")
                        || bioSubType.equals("Right MiddleFinger") || bioSubType.equals("Right LittleFinger")
                        || bioSubType.equals("Right Thumb"))) {
                    LOGGER.error("isValidBIRParams>>BiometricType#" + bioType + ">>BioSubType#" + bioSubType);
                    responseStatus = ResponseStatus.MISSING_INPUT;
                    throw new SDKException(String.valueOf(responseStatus.getStatusCode()), responseStatus.getStatusMessage());
                }
                break;
            case IRIS:
                if (!(bioSubType.equals("UNKNOWN") || bioSubType.equals("Left") || bioSubType.equals("Right"))) {
                    LOGGER.error("isValidBIRParams>>BiometricType#" + bioType + ">>BioSubType#" + bioSubType);
                    responseStatus = ResponseStatus.MISSING_INPUT;
                    throw new SDKException(String.valueOf(responseStatus.getStatusCode()), responseStatus.getStatusMessage());
                }
                break;
            default:
                LOGGER.error("isValidBIRParams>>BiometricType#" + bioType + ">>BioSubType#" + bioSubType);
                responseStatus = ResponseStatus.MISSING_INPUT;
                throw new SDKException(String.valueOf(responseStatus.getStatusCode()), responseStatus.getStatusMessage());
        }
        return true;
    }

    protected boolean isValidBDBData(PurposeType purposeType, BiometricType bioType, String bioSubType,
                                     byte[] bdbData) {
        ResponseStatus responseStatus = null;
        if (bdbData != null && bdbData.length != 0) {
            return isValidBiometericData(purposeType, bioType, bioSubType, Util.encodeToURLSafeBase64(bdbData));
        }

        responseStatus = ResponseStatus.BIOMETRIC_NOT_FOUND_IN_CBEFF;
        throw new SDKException(String.valueOf(responseStatus.getStatusCode()), responseStatus.getStatusMessage());
    }

    protected boolean isValidBiometericData(PurposeType purposeType, BiometricType bioType, String bioSubType,
                                            String bdbData) {
        ResponseStatus responseStatus = null;
        switch (bioType) {
            case FACE:
                return isValidFaceBdb(purposeType, bioSubType, bdbData);
            case FINGER:
                return isValidFingerBdb(purposeType, bioSubType, bdbData);
            case IRIS:
                return isValidIrisBdb(purposeType, bioSubType, bdbData);
            default:
                break;
        }
        responseStatus = ResponseStatus.INVALID_INPUT;
        throw new SDKException(String.valueOf(responseStatus.getStatusCode()), responseStatus.getStatusMessage());
    }

    protected boolean isValidFingerBdb(PurposeType purposeType, String biometricSubType, String bdbData) {
        ResponseStatus responseStatus = null;
        try {
            StringBuilder message = new StringBuilder(
                    "ISOStandardsValidator[ISO19794-4:2011] failed due to below issues:");
            boolean isValid = true;

            ConvertRequestDto requestDto = new ConvertRequestDto();
            requestDto.setModality("Finger");
            requestDto.setVersion("ISO19794_4_2011");
            byte[] bioData = null;
            try {
                bioData = Util.decodeURLSafeBase64(bdbData);
                requestDto.setInputBytes(bioData);
            } catch (Exception e) {
                responseStatus = ResponseStatus.INVALID_INPUT;
                throw new SDKException(String.valueOf(responseStatus.getStatusCode()),
                        responseStatus.getStatusMessage() + " Source not valid base64urlencoded");
            }

            FingerBDIR bdir = FingerDecoder.getFingerBDIR(requestDto);

            if (!FingerISOStandardsValidator.getInstance().isValidFormatIdentifier(bdir.getFormatIdentifier())) {
                message.append("<BR>Invalid Format Identifier for Finger Modality, expected values[0x46495200], but received input value[").append(String.format("0x%08X", bdir.getFormatIdentifier())).append("]");
                isValid = false;
            }

            if (!FingerISOStandardsValidator.getInstance().isValidVersionNumber(bdir.getVersionNumber())) {
                message.append("<BR>Invalid Version Number for Finger Modality, expected values[0x30323000], but received input value[").append(String.format("0x%08X", bdir.getVersionNumber())).append("]");
                isValid = false;
            }

            if (!FingerISOStandardsValidator.getInstance().isValidNoOfRepresentations(bdir.getNoOfRepresentations())) {
                message.append("<BR>Invalid No Of Representations for Finger Modality, expected values[0x0001], but received input value[").append(String.format("0x%04X", bdir.getNoOfRepresentations())).append("]");
                isValid = false;
            }

            if (!FingerISOStandardsValidator.getInstance().isValidRecordLength(bioData != null ? bioData.length : 0,
                    bdir.getRecordLength())) {
                message.append("<BR>Invalid Record Length for Finger Modality, expected values between[0x00000039 and 0xFFFFFFFF], but received input value[").append(String.format("0x%08X", (bioData != null ? bioData.length : 0))).append("]");
                isValid = false;
            }

            if (!FingerISOStandardsValidator.getInstance().isValidCertificationFlag(bdir.getCertificationFlag())) {
                message.append("<BR>Invalid Certification Flag for Finger Modality, expected values[0x00, 0x01], but received input value[").append(String.format("0x%02X", bdir.getCertificationFlag())).append("]");
                isValid = false;
            }

            if (!FingerISOStandardsValidator.getInstance().isValidNoOfFingerPresent(bdir.getNoOfFingerPresent())) {
                message.append("<BR>Invalid No Of Finger Present for Finger Modality, expected values[0x01], but received input value[").append(String.format("0x%02X", bdir.getNoOfFingerPresent())).append("]");
                isValid = false;
            }

            if (!FingerISOStandardsValidator.getInstance()
                    .isValidRepresentationLength(bdir.getRepresentationsLength())) {
                message.append("<BR>Invalid Representation Length for Finger Modality, expected values between[0x00000029 and 0xFFFFFFEF], but received input value[").append(String.format("0x%08X", bdir.getRecordLength())).append("]");
                isValid = false;
            }

           /*
            Todo:Removed Environment variables as discussed it was not used.Need to add if required.
            LOGGER.info("isValidFingerBdb>>timestamp check >> " + this.getEnv().getProperty(SdkConstant.SDK_CHECK_ISO_TIMESTAMP_FORMAT, Boolean.class, true));

            if (this.getEnv().getProperty(SdkConstant.SDK_CHECK_ISO_TIMESTAMP_FORMAT, Boolean.class, true)) {
                if (!FingerISOStandardsValidator.getInstance().isValidCaptureDateTime(bdir.getCaptureYear(),
                        bdir.getCaptureMonth(), bdir.getCaptureDay(), bdir.getCaptureHour(), bdir.getCaptureMinute(),
                        bdir.getCaptureSecond(), bdir.getCaptureMilliSecond())) {
                    message.append("<BR>Invalid CaptureDateTime for Finger Modality, The capture date and time field shall \r\n" + "indicate when the capture of this \r\n" + "representation stated in Coordinated \r\n" + "Universal Time (UTC). The capture date \r\n" + "and time field shall consist of 9 bytes., but received input value[").append(bdir.getCaptureDateTime()).append("]");
                    isValid = false;
                }
            }
            */
            if (!FingerISOStandardsValidator.getInstance()
                    .isValidCaptureDeviceTechnologyIdentifier(bdir.getCaptureDeviceTechnologyIdentifier())) {
                message.append("<BR>Invalid Capture Device Technology Identifier for Finger Modality, expected values between[0x00 and 0x14], but received input value[").append(String.format("0x%02X", bdir.getCaptureDeviceTechnologyIdentifier())).append("]");
                isValid = false;
            }

            if (!FingerISOStandardsValidator.getInstance()
                    .isValidCaptureDeviceVendor(bdir.getCaptureDeviceVendorIdentifier())) {
                message.append("<BR>Invalid Capture Device Vendor Identifier for Finger Modality, expected values between[0x0000 and 0xFFFF], but received input value[").append(String.format("0x%04X", bdir.getCaptureDeviceVendorIdentifier())).append("]");
                isValid = false;
            }

            if (!FingerISOStandardsValidator.getInstance().isValidCaptureDeviceType(
                    bdir.getCaptureDeviceVendorIdentifier(), bdir.getCaptureDeviceTypeIdentifier())) {
                message.append("<BR>Invalid Capture Device Type Identifier for Finger Modality, expected values between[0x0000 and 0xFFFF], but received input value[").append(String.format("0x%04X", bdir.getCaptureDeviceTypeIdentifier())).append("]");
                isValid = false;
            }

            if (!FingerISOStandardsValidator.getInstance().isValidNoOfQualityBlocks(bdir.getNoOfQualityBlocks())) {
                message.append("<BR>Invalid No Of Quality Blocks value for Finger Modality, expected values between[0x00 and 0xFF], but received input value[").append(String.format("0x%02X", bdir.getNoOfQualityBlocks())).append("]");
                isValid = false;
            }

            if (bdir.getNoOfQualityBlocks() > 0) {
                for (FingerQualityBlock qualityBlock : bdir.getQualityBlocks()) {
                    if (!FingerISOStandardsValidator.getInstance()
                            .isValidQualityScore(qualityBlock.getQualityScore())) {
                        message.append("<BR>Invalid Quality Score value for Finger Modality, expected values between[{0x00 and 0x64}, {0xFF}], but received input value[").append(String.format("0x%02X", qualityBlock.getQualityScore())).append("]");
                        isValid = false;
                    }

                    if (!FingerISOStandardsValidator.getInstance()
                            .isValidQualityAlgorithmIdentifier(qualityBlock.getQualityAlgorithmIdentifier())) {
                        message.append("<BR>Invalid Quality Algorithm Identifier for Finger Modality, expected values between[0x0000 and 0xFFFF], but received input value[").append(String.format("0x%04X", qualityBlock.getQualityAlgorithmIdentifier())).append("]");
                        isValid = false;
                    }

                    if (!FingerISOStandardsValidator.getInstance().isValidQualityAlgorithmVendorIdentifier(
                            qualityBlock.getQualityAlgorithmVendorIdentifier())) {
                        message.append("<BR>Invalid Quality Algorithm Vendor Identifier for Finger Modality, expected values between[0x0000 and 0xFFFF], but received input value[").append(String.format("0x%04X", qualityBlock.getQualityAlgorithmVendorIdentifier())).append("]");
                        isValid = false;
                    }
                }
            }

            if (!FingerISOStandardsValidator.getInstance()
                    .isValidNoOfCertificationBlocks(bdir.getNoOfCertificationBlocks())) {
                message.append("<BR>Invalid No Of Certification Blocks for Finger Modality, expected values between[0x00 and 0xFF], but received input value[").append(String.format("0x%02X", bdir.getNoOfCertificationBlocks())).append("]");
                isValid = false;
            }

            if (bdir.getNoOfCertificationBlocks() > 0) {
                for (FingerCertificationBlock fingerCertificationBlock : bdir.getCertificationBlocks()) {
                    if (!FingerISOStandardsValidator.getInstance()
                            .isValidCertificationAuthorityID(fingerCertificationBlock.getCertificationAuthorityID())) {
                        message.append("<BR>Invalid Certification AuthorityID for Finger Modality, expected values between[0x0000 and 0xFFFF], but received input value[").append(String.format("0x%04X",
                                fingerCertificationBlock.getCertificationAuthorityID())).append("]");
                        isValid = false;
                    }

                    if (!FingerISOStandardsValidator.getInstance().isValidCertificationSchemeIdentifier(
                            fingerCertificationBlock.getCertificationSchemeIdentifier())) {
                        message.append("<BR>Invalid Certification Scheme Identifier for Finger Modality, expected values between[0x00 and 0xFF], but received input value[").append(String.format("0x%02X",
                                fingerCertificationBlock.getCertificationSchemeIdentifier())).append("]");
                        isValid = false;
                    }
                }
            }

            int fingerPosition = bdir.getFingerPosition();
            if (!isValidFingerPosition(fingerPosition, biometricSubType)) {
                message.append("<BR>Invalid Finger Position Value for Finger Modality, expected values between[0x00 and 0x0A], but received input value[").append(String.format("0x%02X", bdir.getFingerPosition())).append("}]");
                isValid = false;
            }

            if (!FingerISOStandardsValidator.getInstance().isValidRepresentationsNo(bdir.getRepresentationNo())) {
                message.append("<BR>Invalid Representations No Value for Finger Modality, expected values between[0x00 and 0x0F], but received input value[").append(String.format("0x%02X", bdir.getRepresentationNo())).append("]");
                isValid = false;
            }

            //Used to check the image based on PIXELS_PER_INCH or PIXELS_PER_CM
            int scaleUnitsType = bdir.getScaleUnits();
            if (!FingerISOStandardsValidator.getInstance().isValidScaleUnits(scaleUnitsType)) {
                message.append("<BR>Invalid Scale Unit Type Value for Finger Modality, expected values[0x01, 0x02], but received input value[").append(String.format("0x%02X", scaleUnitsType)).append("]");
                isValid = false;
            }

            int scanSpatialSamplingRateHorizontal = bdir.getCaptureDeviceSpatialSamplingRateHorizontal();
            if (!FingerISOStandardsValidator.getInstance()
                    .isValidScanSpatialSamplingRateHorizontal(scanSpatialSamplingRateHorizontal)) {
                message.append("<BR>Invalid Device Scan Spatial Sampling Rate Horizontal for Finger Modality, expected values between[0x01EA and 0x03F2], but received input value[").append(String.format("0x%04X", scanSpatialSamplingRateHorizontal)).append("]");
                isValid = false;
            }

            int scanSpatialSamplingRateVertical = bdir.getCaptureDeviceSpatialSamplingRateVertical();
            if (!FingerISOStandardsValidator.getInstance()
                    .isValidScanSpatialSamplingRateVertical(scanSpatialSamplingRateVertical)) {
                message.append("<BR>Invalid Device Scan Spatial Sampling Rate Vertical for Finger Modality, expected values between[0x01EA and 0x03F2], but received input value[").append(String.format("0x%04X", scanSpatialSamplingRateVertical)).append("]");
                isValid = false;
            }

            if (!FingerISOStandardsValidator.getInstance().isValidImageSpatialSamplingRateHorizontal(
                    scanSpatialSamplingRateHorizontal, bdir.getImageSpatialSamplingRateHorizontal())) {
                message.append("<BR>Invalid Image Spatial SamplingRate Horizontal for Finger Modality, expected values between[0x01EA and 0x03F2] And less than or equal to ScanSpatialSamplingRateHorizontal value of ").append(String.format("0x%04X", scanSpatialSamplingRateHorizontal)).append(", but received input value[").append(String.format("0x%04X", bdir.getImageSpatialSamplingRateHorizontal())).append("]");
                isValid = false;
            }

            if (!FingerISOStandardsValidator.getInstance().isValidImageSpatialSamplingRateVertical(
                    scanSpatialSamplingRateVertical, bdir.getImageSpatialSamplingRateVertical())) {
                message.append("<BR>Invalid Device Scan Spatial Sampling Rate Vertical for Finger Modality, expected values between[0x01EA and 0x03F2] And less than or equal to ScanSpatialSamplingRateVertical value of ").append(String.format("0x%04X", scanSpatialSamplingRateVertical)).append(", but received input value[").append(String.format("0x%04X", bdir.getImageSpatialSamplingRateVertical())).append("]");
                isValid = false;
            }

            byte[] inImageData = bdir.getImage();
            if (!FingerISOStandardsValidator.getInstance().isValidBitDepth(inImageData, bdir.getBitDepth())) {
                message.append("<BR>Invalid Image Bit Depth Value for Finger Modality, expected values[0x08], but received input value[").append(String.format("0x%02X", bdir.getBitDepth())).append("]");
                isValid = false;
            }

            int compressionType = bdir.getCompressionType();
            if (!(compressionType == FingerImageCompressionType.JPEG_2000_LOSSY
                    || compressionType == FingerImageCompressionType.WSQ
                    || compressionType == FingerImageCompressionType.JPEG_2000_LOSS_LESS)) {
                message.append("<BR>Invalid Image Compression Type for Finger Modality, expected values[{JPEG_2000_LOSSY(0x04) or WSQ(0x02) or JPEG_2000_LOSS_LESS(0x05)}], but received input value[" + " (").append(String.format("0x%02X", compressionType)).append(")]");
                isValid = false;
            }

            if (!FingerISOStandardsValidator.getInstance().isValidImageImpressionType(bdir.getImpressionType())) {
                message.append("<BR>Invalid Image Impression Type for Finger Modality, expected values between[{0x00 and 0x0F} or 0x18 or 0x1C or 0x1D], " + " but received input value[").append(String.format("0x%02X", bdir.getImpressionType())).append("]");
                isValid = false;
            }

            if (!FingerISOStandardsValidator.getInstance().isValidImageDataLength(inImageData, bdir.getImageLength())) {
                message.append("<BR>Invalid Image Data Length for Finger Modality, expected values[0x00000001 and 0xFFFFFFFF], but received input value[").append(String.format("0x%08X", bdir.getImageLength())).append("]");
                isValid = false;
            }

            // TODO check the condition: imagedata
           // can check image type for auth and reg
            if (!isValid) {
                responseStatus = ResponseStatus.INVALID_INPUT;
                throw new SDKException(String.valueOf(responseStatus.getStatusCode()),
                        responseStatus.getStatusMessage() + " " + message.toString());
            }
            return true;
        } catch (Exception ex) {
            responseStatus = ResponseStatus.INVALID_INPUT;
            throw new SDKException(String.valueOf(responseStatus.getStatusCode()),
                    responseStatus.getStatusMessage() + " " + ex.getLocalizedMessage());
        }
    }

    protected boolean isValidFingerPosition(int fingerPosition, String biometricSubType) {
        boolean isValid = false;
        switch (biometricSubType) {
            case "UNKNOWN":
                isValid = true;
                break;
            case "Left IndexFinger":
                if (fingerPosition == FingerPosition.LEFT_INDEX_FINGER)
                    isValid = true;
                break;
            case "Left MiddleFinger":
                if (fingerPosition == FingerPosition.LEFT_MIDDLE_FINGER)
                    isValid = true;
                break;
            case "Left RingFinger":
                if (fingerPosition == FingerPosition.LEFT_RING_FINGER)
                    isValid = true;
                break;
            case "Left LittleFinger":
                if (fingerPosition == FingerPosition.LEFT_LITTLE_FINGER)
                    isValid = true;
                break;
            case "Left Thumb":
                if (fingerPosition == FingerPosition.LEFT_THUMB)
                    isValid = true;
                break;
            case "Right IndexFinger":
                if (fingerPosition == FingerPosition.RIGHT_INDEX_FINGER)
                    isValid = true;
                break;
            case "Right MiddleFinger":
                if (fingerPosition == FingerPosition.RIGHT_MIDDLE_FINGER)
                    isValid = true;
                break;
            case "Right RingFinger":
                if (fingerPosition == FingerPosition.RIGHT_RING_FINGER)
                    isValid = true;
                break;
            case "Right LittleFinger":
                if (fingerPosition == FingerPosition.RIGHT_LITTLE_FINGER)
                    isValid = true;
                break;
            case "Right Thumb":
                if (fingerPosition == FingerPosition.RIGHT_THUMB)
                    isValid = true;
                break;
            default:
                break;
        }
        return isValid;
    }

    protected boolean isValidIrisBdb(PurposeType purposeType, String biometricSubType, String bdbData) {
        ResponseStatus responseStatus = null;
        try {
            StringBuilder message = new StringBuilder(
                    "ISOStandardsValidator[ISO19794-6:2011] failed due to below issues:");
            boolean isValid = true;

            ConvertRequestDto requestDto = new ConvertRequestDto();
            requestDto.setModality("Iris");
            requestDto.setVersion("ISO19794_6_2011");
            byte[] bioData = null;
            try {
                bioData = Util.decodeURLSafeBase64(bdbData);
                requestDto.setInputBytes(bioData);
            } catch (Exception e) {
                responseStatus = ResponseStatus.INVALID_INPUT;
                throw new SDKException(String.valueOf(responseStatus.getStatusCode()),
                        responseStatus.getStatusMessage() + " Source not valid base64urlencoded");
            }

            IrisBDIR bdir = IrisDecoder.getIrisBDIR(requestDto);

            if (!IrisISOStandardsValidator.getInstance().isValidFormatIdentifier(bdir.getFormatIdentifier())) {
                message.append("<BR>Invalid Format Identifier for Iris Modality, expected values[0x49495200], but received input value[").append(String.format("0x%08X", bdir.getFormatIdentifier())).append("]");
                isValid = false;
            }

            if (!IrisISOStandardsValidator.getInstance().isValidVersionNumber(bdir.getVersionNumber())) {
                message.append("<BR>Invalid Version Number for Iris Modality, expected values[0x30323000], but received input value[").append(String.format("0x%08X", bdir.getVersionNumber())).append("]");
                isValid = false;
            }

            int noOfRepresentations = bdir.getNoOfRepresentations();
            if (!IrisISOStandardsValidator.getInstance().isValidNoOfRepresentations(noOfRepresentations)) {
                message.append("<BR>Invalid No Of Representations for Iris Modality, expected values[0x0001], but received input value[").append(String.format("0x%04X", bdir.getNoOfRepresentations())).append("]");
                isValid = false;
            }

            if (!IrisISOStandardsValidator.getInstance().isValidRecordLength(bioData != null ? bioData.length : 0,
                    bdir.getRecordLength())) {
                message.append("<BR>Invalid Record Length for Iris Modality, expected values between[0x00000045 and 0xFFFFFFFF], but received input value[").append(String.format("0x%08X", (bioData != null ? bioData.length : 0))).append("] Or Data Length mismatch[").append(bioData.length).append("!= ").append(bdir.getRecordLength()).append("]");
                isValid = false;
            }

            if (!IrisISOStandardsValidator.getInstance().isValidCertificationFlag(bdir.getCertificationFlag())) {
                message.append("<BR>Invalid Certification Flag for Iris Modality, expected values[0x00], but received input value[").append(String.format("0x%02X", bdir.getCertificationFlag())).append("]");
                isValid = false;
            }

            int noOfEyesPresent = bdir.getNoOfEyesPresent();
            if (!IrisISOStandardsValidator.getInstance().isValidNoOfEyesRepresented(bdir.getNoOfEyesPresent())) {
                message.append("<BR>Invalid No Of Eyes Present for Iris Modality, expected values[0x00, 0x01], but received input value[").append(String.format("0x%02X", bdir.getNoOfEyesPresent())).append("]");
                isValid = false;
            }

            if (noOfRepresentations != noOfEyesPresent) {
                message.append("<BR>Invalid No Of Eyes Present[").append(String.format("0x%04X", noOfEyesPresent)).append("] for Iris Modality, For given No Of Representations[").append(String.format("0x%04X", noOfRepresentations)).append("]");
                isValid = false;
            }

            if (!IrisISOStandardsValidator.getInstance().isValidRepresentationLength(bdir.getRepresentationsLength())) {
                message.append("<BR>Invalid Representation Length for Iris Modality, expected values between[0x00000035 And 0xFFFFFFEF], but received input value[").append(String.format("0x%08X", bdir.getRecordLength())).append("]");
                isValid = false;
            }

           /*
            Todo:Removed Environment variables as discussed it was not used.Need to add if required.
            LOGGER.info("isValidIrisBdb>>timestamp check >> " + this.getEnv().getProperty(SdkConstant.SDK_CHECK_ISO_TIMESTAMP_FORMAT, Boolean.class, true));

            if (this.getEnv().getProperty(SdkConstant.SDK_CHECK_ISO_TIMESTAMP_FORMAT, Boolean.class, true)) {
                if (!IrisISOStandardsValidator.getInstance().isValidCaptureDateTime(bdir.getCaptureYear(),
                        bdir.getCaptureMonth(), bdir.getCaptureDay(), bdir.getCaptureHour(), bdir.getCaptureMinute(),
                        bdir.getCaptureSecond(), bdir.getCaptureMilliSecond())) {
                    message.append("<BR>Invalid CaptureDateTime for Iris Modality, The capture date and time field shall \r\n" + "indicate when the capture of this \r\n" + "representation stated in Coordinated \r\n" + "Universal Time (UTC). The capture date \r\n" + "and time field shall consist of 9 bytes., but received input value[").append(bdir.getCaptureDateTime()).append("]");
                    isValid = false;
                }
            }*/
            if (!IrisISOStandardsValidator.getInstance()
                    .isValidCaptureDeviceTechnologyIdentifier(bdir.getCaptureDeviceTechnologyIdentifier())) {
                message.append("<BR>Invalid Capture Device Technology Identifier for Iris Modality, expected values[0x00, 0x01], but received input value[").append(String.format("0x%02X", bdir.getCaptureDeviceTechnologyIdentifier())).append("]");
                isValid = false;
            }

            if (!IrisISOStandardsValidator.getInstance()
                    .isValidCaptureDeviceVendor(bdir.getCaptureDeviceVendorIdentifier())) {
                message.append("<BR>Invalid Capture Device Vendor Identifier for Iris Modality, expected values between[0x0000 and 0xFFFF], but received input value[").append(String.format("0x%04X", bdir.getCaptureDeviceVendorIdentifier())).append("]");
                isValid = false;
            }

            if (!IrisISOStandardsValidator.getInstance().isValidCaptureDeviceType(
                    bdir.getCaptureDeviceVendorIdentifier(), bdir.getCaptureDeviceTypeIdentifier())) {
                message.append("<BR>Invalid Capture Device Type Identifier for Iris Modality, expected values between[0x0000 and 0xFFFF], but received input value[").append(String.format("0x%04X", bdir.getCaptureDeviceTypeIdentifier())).append("]");
                isValid = false;
            }

            if (!IrisISOStandardsValidator.getInstance().isValidNoOfQualityBlocks(bdir.getNoOfQualityBlocks())) {
                message.append("<BR>Invalid No Of Quality Blocks value for Iris Modality, expected values between [0x00 and 0xFF], but received input value[").append(String.format("0x%02X", bdir.getNoOfQualityBlocks())).append("]");
                isValid = false;
            }

            if (bdir.getNoOfQualityBlocks() > 0) {
                for (IrisQualityBlock qualityBlock : bdir.getQualityBlocks()) {
                    if (!IrisISOStandardsValidator.getInstance().isValidQualityScore(qualityBlock.getQualityScore())) {
                        message.append("<BR>Invalid Quality Score value for Iris Modality, expected values between[0x00 and 0x64], but received input value[").append(String.format("0x%02X", qualityBlock.getQualityScore())).append("]");
                        isValid = false;
                    }

                    if (!IrisISOStandardsValidator.getInstance()
                            .isValidQualityAlgorithmIdentifier(qualityBlock.getQualityAlgorithmIdentifier())) {
                        message.append("<BR>Invalid Quality Algorithm Identifier for Iris Modality, expected values between[0x0000 and 0xFFFF], but received input value[").append(String.format("0x%04X", qualityBlock.getQualityAlgorithmIdentifier())).append("]");
                        isValid = false;
                    }

                    if (!IrisISOStandardsValidator.getInstance().isValidQualityAlgorithmVendorIdentifier(
                            qualityBlock.getQualityAlgorithmVendorIdentifier())) {
                        message.append("<BR>Invalid Quality Algorithm Vendor Identifier for Iris Modality, expected values between[0x0000 and 0xFFFF], but received input value[").append(String.format("0x%04X", qualityBlock.getQualityAlgorithmVendorIdentifier())).append("]");
                        isValid = false;
                    }
                }
            }

            if (!IrisISOStandardsValidator.getInstance().isValidNoOfRepresentation(bdir.getRepresentationNo())) {
                message.append("<BR>Invalid No Of Representation for Iris Modality, expected values[0x01], but received input value[").append(String.format("0x%02X", bdir.getRepresentationNo())).append("]");
                isValid = false;
            }

            int eyeLabel = bdir.getEyeLabel();
            if (!isValidEyeLabel(eyeLabel, biometricSubType)) {
                message.append("<BR>Invalid Iris Eye Label Value for Iris Modality, expected values[0x00, 0x01, 0x02}], but received input value[" + "{").append(String.format("0x%02X", bdir.getEyeLabel())).append("}]");
                isValid = false;
            }

            int imageType = bdir.getImageType();
            if (!(imageType == ImageType.CROPPED_AND_MASKED || imageType == ImageType.CROPPED)) {
                message.append("<BR>Invalid Image Type No Value Irisnger Modality, expected values[0x03, 0x07], but received input value[" + "{").append(String.format("0x%02X", bdir.getImageType())).append("}]");
                isValid = false;
            }

            if (!IrisISOStandardsValidator.getInstance().isValidImageFromat(bdir.getImageFormat())) {
                message.append("<BR>Invalid Image Format Value for Iris Modality, expected values[0x0A], but received input value[").append(String.format("0x%02X", bdir.getImageFormat())).append("]");
                isValid = false;
            }

            if (!IrisISOStandardsValidator.getInstance()
                    .isValidImageHorizontalOrientation(bdir.getHorizontalOrientation())) {
                message.append("<BR>Invalid Image Horizontal Orientation for Iris Modality, expected values[0x00, 0x01, 0x02], but received input value[").append(String.format("0x%02X", bdir.getHorizontalOrientation())).append("]");
                isValid = false;
            }

            if (!IrisISOStandardsValidator.getInstance()
                    .isValidImageVerticalOrientation(bdir.getVerticalOrientation())) {
                message.append("<BR>Invalid Image Vertical Orientation for Iris Modality, expected values[0x00, 0x01, 0x02], but received input value[").append(String.format("0x%02X", bdir.getVerticalOrientation())).append("]");
                isValid = false;
            }

            int compressionType = bdir.getCompressionType();
            if (!(compressionType == IrisImageCompressionType.JPEG_LOSSY
                    || compressionType == IrisImageCompressionType.JPEG_LOSSLESS_OR_NONE)) {
                message.append("<BR>Invalid Image Compression Type for Iris Modality, expected values[JPEG_2000_LOSSY(0x02), JPEG_2000_LOSS_LESS(0x01)], but received input value[" + "(").append(String.format("0x%02X", compressionType)).append(")]");
                isValid = false;
            }

            byte[] inImageData = bdir.getImage();

            if (!IrisISOStandardsValidator.getInstance().isValidBitDepth(inImageData, bdir.getBitDepth())) {
                message.append("<BR>Invalid Image Bit Depth Value for Iris Modality, expected values[0x08(Grayscale)], but received input value[").append(String.format("0x%02X", bdir.getBitDepth())).append("]");
                isValid = false;
            }

            if (!IrisISOStandardsValidator.getInstance().isValidRange(bdir.getRange())) {
                message.append("<BR>Invalid Range Value for Iris Modality, expected values between[0x0000 and 0xFFFF], but received input value[").append(String.format("0x%04X", bdir.getRange())).append("]");
                isValid = false;
            }

            if (!IrisISOStandardsValidator.getInstance().isValidRollAngleOfEye(bdir.getRollAngleOfEye())) {
                message.append("<BR>Invalid Roll Angle Of Eye Value for Iris Modality, expected values between[0x0000 and 0xFFFF], but received input value[").append(String.format("0x%04X", bdir.getRollAngleOfEye())).append("]");
                isValid = false;
            }

            if (!IrisISOStandardsValidator.getInstance().isValidRollAngleUncertainty(bdir.getRollAngleUncertainty())) {
                message.append("<BR>Invalid Roll Angle Uncertainty Value for Iris Modality, expected values between[0x0000 and 0xFFFF], but received input value[").append(String.format("0x%04X", bdir.getRollAngleUncertainty())).append("]");
                isValid = false;
            }

            if (!IrisISOStandardsValidator.getInstance().isValidIrisCenterSmallestX(bdir.getIrisCenterSmallestX())) {
                message.append("<BR>Invalid Iris Center Smallest X Value for Iris Modality, expected values between[0x0000 and 0xFFFF], but received input value[").append(String.format("0x%04X", bdir.getIrisCenterSmallestX())).append("]");
                isValid = false;
            }

            if (!IrisISOStandardsValidator.getInstance().isValidIrisCenterLargestX(bdir.getIrisCenterLargestX())) {
                message.append("<BR>Invalid Iris Center Largest X Value for Iris Modality, expected values between[0x0000 and 0xFFFF], but received input value[").append(String.format("0x%04X", bdir.getIrisCenterLargestX())).append("]");
                isValid = false;
            }

            if (!IrisISOStandardsValidator.getInstance().isValidIrisCenterSmallestY(bdir.getIrisCenterSmallestY())) {
                message.append("<BR>Invalid Iris Center Smallest Y Value for Iris Modality, expected values between[0x0000 and 0xFFFF], but received input value[").append(String.format("0x%04X", bdir.getIrisCenterSmallestY())).append("]");
                isValid = false;
            }

            if (!IrisISOStandardsValidator.getInstance().isValidIrisCenterLargestY(bdir.getIrisCenterLargestY())) {
                message.append("<BR>Invalid Iris Center Largest Y Value for Iris Modality, expected values between[0x0000 and 0xFFFF], but received input value[").append(String.format("0x%04X", bdir.getIrisCenterLargestY())).append("]");
                isValid = false;
            }

            if (!IrisISOStandardsValidator.getInstance().isValidIrisDiameterSmallest(bdir.getIrisDiameterSmallest())) {
                message.append("<BR>Invalid Iris Diameter Smallest Value for Iris Modality, expected values between[0x0000 and 0xFFFF], but received input value[").append(String.format("0x%04X", bdir.getIrisDiameterSmallest())).append("]");
                isValid = false;
            }

            if (!IrisISOStandardsValidator.getInstance().isValidIrisDiameterLargest(bdir.getIrisDiameterLargest())) {
                message.append("<BR>Invalid Iris Diameter Largest Value for Iris Modality, expected values between[0x0000 and 0xFFFF], but received input value[").append(String.format("0x%04X", bdir.getIrisDiameterLargest())).append("]");
                isValid = false;
            }

            if (!IrisISOStandardsValidator.getInstance().isValidImageDataLength(inImageData, bdir.getImageLength())) {
                message.append("<BR>Invalid Image Data Length for Iris Modality, expected values between[0x00000001 and 0xFFFFFFFF], but received input value[").append(String.format("0x%08X", bdir.getImageLength())).append("]");
                isValid = false;
            }

            // TODO check the condition: imagedata
            if (!isValid) {
                responseStatus = ResponseStatus.INVALID_INPUT;
                throw new SDKException(String.valueOf(responseStatus.getStatusCode()),
                        responseStatus.getStatusMessage() + " " + message.toString());
            }
            // can check image type for auth and reg
            return true;
        } catch (Exception ex) {
            responseStatus = ResponseStatus.INVALID_INPUT;
            throw new SDKException(String.valueOf(responseStatus.getStatusCode()),
                    responseStatus.getStatusMessage() + " " + ex.getLocalizedMessage());
        }
    }

    protected boolean isValidEyeLabel(int eyeLabel, String biometricSubType) {
        boolean isValid = false;
        switch (biometricSubType) {
            case "UNKNOWN":
                isValid = true;
                break;
            case "Left":
                if (eyeLabel == EyeLabel.LEFT)
                    isValid = true;
                break;
            case "Right":
                if (eyeLabel == EyeLabel.RIGHT)
                    isValid = true;
                break;
            default:
                break;
        }
        return isValid;
    }

    protected boolean isValidFaceBdb(PurposeType purposeType, String biometricSubType, String bdbData) {
        ResponseStatus responseStatus = null;
        try {
            StringBuilder message = new StringBuilder(
                    "ISOStandardsValidator[ISO19794-5:2011] failed due to below issues:");
            boolean isValid = true;

            ConvertRequestDto requestDto = new ConvertRequestDto();
            requestDto.setModality("Face");
            requestDto.setVersion("ISO19794_5_2011");
            byte[] bioData = null;
            try {
                bioData = Util.decodeURLSafeBase64(bdbData);
                requestDto.setInputBytes(bioData);
            } catch (Exception e) {
                responseStatus = ResponseStatus.INVALID_INPUT;
                throw new SDKException(String.valueOf(responseStatus.getStatusCode()), responseStatus.getStatusMessage());
            }
            FaceBDIR bdir = FaceDecoder.getFaceBDIR(requestDto);

            if (!FaceISOStandardsValidator.getInstance().isValidFormatIdentifier(bdir.getFormatIdentifier())) {
                message.append("<BR>Invalid Format Identifier for Face Modality, expected values[0x46414300], but received input value[").append(String.format("0x%08X", bdir.getFormatIdentifier())).append("]");
                isValid = false;
            }

            if (!FaceISOStandardsValidator.getInstance().isValidVersionNumber(bdir.getVersionNumber())) {
                message.append("<BR>Invalid Version Number for Face Modality, expected values[0x30333000], but received input value[").append(String.format("0x%08X", bdir.getVersionNumber())).append("]");
                isValid = false;
            }

            if (!FaceISOStandardsValidator.getInstance().isValidNoOfRepresentations(bdir.getNoOfRepresentations())) {
                message.append("<BR>Invalid No Of Representations for Face Modality, expected values[0x0001], but received input value[").append(String.format("0x%04X", bdir.getNoOfRepresentations())).append("]");
                isValid = false;
            }

            if (!FaceISOStandardsValidator.getInstance().isValidRecordLength(bioData != null ? bioData.length : 0,
                    bdir.getRecordLength())) {
                message.append("<BR>Invalid Record Length for Face Modality, expected values between[0x00000001 and 0xFFFFFFFF], but received input value[").append(String.format("0x%08X", (bioData != null ? bioData.length : 0))).append("]");
                isValid = false;
            }

            if (!FaceISOStandardsValidator.getInstance().isValidCertificationFlag(bdir.getCertificationFlag())) {
                message.append("<BR>Invalid Certification Flag for Face Modality, expected values[0x00], but received input value[").append(String.format("0x%02X", bdir.getCertificationFlag())).append("]");
                isValid = false;
            }

            if (!FaceISOStandardsValidator.getInstance().isValidTemporalSemantics(bdir.getTemporalSemantics())) {
                message.append("<BR>Invalid Certification Flag for Face Modality, expected values[0x0000], but received input value[").append(String.format("0x%04X", bdir.getTemporalSemantics())).append("]");
                isValid = false;
            }

            if (!FaceISOStandardsValidator.getInstance().isValidRepresentationLength(bdir.getRecordLength())) {
                message.append("<BR>Invalid Representation Length for Face Modality, expected values between[0x00000033 and 0xFFFFFFEF], but received input value[").append(String.format("0x%08X", bdir.getRecordLength())).append("]");
                isValid = false;
            }

           /*
            Todo:Removed Environment variables as discussed it was not used.Need to add if required.
            LOGGER.info("isValidFaceBdb>>timestamp check >> " + this.getEnv().getProperty(SdkConstant.SDK_CHECK_ISO_TIMESTAMP_FORMAT, Boolean.class, true));

            if (this.getEnv().getProperty(SdkConstant.SDK_CHECK_ISO_TIMESTAMP_FORMAT, Boolean.class, true)) {
                if (!FaceISOStandardsValidator.getInstance().isValidCaptureDateTime(bdir.getCaptureYear(),
                        bdir.getCaptureMonth(), bdir.getCaptureDay(), bdir.getCaptureHour(), bdir.getCaptureMinute(),
                        bdir.getCaptureSecond(), bdir.getCaptureMilliSecond())) {
                    message.append("<BR>Invalid CaptureDateTime for Face Modality, The capture date and time field shall \r\n" + "indicate when the capture of this \r\n" + "representation stated in Coordinated \r\n" + "Universal Time (UTC). The capture date \r\n" + "and time field shall consist of 9 bytes., but received input value[").append(bdir.getCaptureDateTime()).append("]");
                    isValid = false;
                }
            }*/
            if (!FaceISOStandardsValidator.getInstance()
                    .isValidCaptureDeviceTechnologyIdentifier(bdir.getCaptureDeviceTechnologyIdentifier())) {
                message.append("<BR>Invalid Capture Device Technology Identifier for Face Modality, expected values between[{0x00 and 0x06}, {0x80 and 0xFF}], but received input value[").append(String.format("0x%02X", bdir.getCaptureDeviceTechnologyIdentifier())).append("]");
                isValid = false;
            }

            if (!FaceISOStandardsValidator.getInstance()
                    .isValidCaptureDeviceVendor(bdir.getCaptureDeviceVendorIdentifier())) {
                message.append("<BR>Invalid Capture Device Vendor Identifier for Face Modality, expected values between[0x0000 and 0xFFFF], but received input value[").append(String.format("0x%04X", bdir.getCaptureDeviceVendorIdentifier())).append("]");
                isValid = false;
            }

            if (!FaceISOStandardsValidator.getInstance().isValidCaptureDeviceType(
                    bdir.getCaptureDeviceVendorIdentifier(), bdir.getCaptureDeviceTypeIdentifier())) {
                message.append("<BR>Invalid Capture Device Type Identifier for Face Modality, expected values between[0x0000 and 0xFFFF], but received input value[").append(String.format("0x%04X", bdir.getCaptureDeviceTypeIdentifier())).append("]");
                isValid = false;
            }

            if (!FaceISOStandardsValidator.getInstance().isValidNoOfQualityBlocks(bdir.getNoOfQualityBlocks())) {
                message.append("<BR>Invalid No Of Quality Blocks value for Face Modality, expected values between[0x00 and 0xFF], but received input value[").append(String.format("0x%02X", bdir.getNoOfQualityBlocks())).append("]");
                isValid = false;
            }

            if (bdir.getNoOfQualityBlocks() > 0) {
                for (FaceQualityBlock qualityBlock : bdir.getQualityBlocks()) {
                    if (!FaceISOStandardsValidator.getInstance().isValidQualityScore(qualityBlock.getQualityScore())) {
                        message.append("<BR>Invalid Quality Score value for Face Modality, expected values between[{0x00 and 0x64}, {0xFF}], but received input value[").append(String.format("0x%02X", qualityBlock.getQualityScore())).append("]");
                        isValid = false;
                    }

                    if (!FaceISOStandardsValidator.getInstance()
                            .isValidQualityAlgorithmIdentifier(qualityBlock.getQualityAlgorithmIdentifier())) {
                        message.append("<BR>Invalid Quality Algorithm Identifier for Face Modality, expected values between[0x0000 and 0xFFFF], but received input value[").append(String.format("0x%04X", qualityBlock.getQualityAlgorithmIdentifier())).append("]");
                        isValid = false;
                    }

                    if (!FaceISOStandardsValidator.getInstance().isValidQualityAlgorithmVendorIdentifier(
                            qualityBlock.getQualityAlgorithmVendorIdentifier())) {
                        message.append("<BR>Invalid Quality Algorithm Vendor Identifier for Face Modality, expected values between[0x0000 and 0xFFFF], but received input value[").append(String.format("0x%04X", qualityBlock.getQualityAlgorithmVendorIdentifier())).append("]");
                        isValid = false;
                    }
                }
            }

            if (!FaceISOStandardsValidator.getInstance().isValidNoOfLandmarkPoints(bdir.getNoOfLandMarkPoints())) {
                message.append("<BR>Invalid No Of Landmark Points for Face Modality, expected values between[0x0000 and 0xFFFF], but received input value[").append(String.format("0x%04X", bdir.getNoOfLandMarkPoints())).append("]");
                isValid = false;
            }

            if (!FaceISOStandardsValidator.getInstance().isValidGender(bdir.getGender())) {
                message.append("<BR>Invalid Gender value for Face Modality, expected values[0x00, 0x01, 0x02, 0xFF], but received input value[").append(String.format("0x%02X", bdir.getGender())).append("]");
                isValid = false;
            }

            if (!FaceISOStandardsValidator.getInstance().isValidEyeColour(bdir.getEyeColor())) {
                message.append("<BR>Invalid Eye Colour value for Face Modality, expected values between[{0x00 and 0x07}, {0xFF}], but received input value[").append(String.format("0x%02X", bdir.getEyeColor())).append("]");
                isValid = false;
            }

            if (!FaceISOStandardsValidator.getInstance().isValidHairColour(bdir.getHairColor())) {
                message.append("<BR>Invalid Hair Colour Value for Face Modality, expected values between[{0x00 and 0x07}, {0xFF}], but received input value[").append(String.format("0x%02X", bdir.getHairColor())).append("]");
                isValid = false;
            }

            if (!FaceISOStandardsValidator.getInstance().isValidSubjectHeight(bdir.getSubjectHeight())) {
                message.append("<BR>Invalid Subject Height Value for Face Modality, expected values between[0x00 and 0xFF], but received input value[").append(String.format("0x%02X", bdir.getSubjectHeight())).append("]");
                isValid = false;
            }

            if (!FaceISOStandardsValidator.getInstance().isValidFeatureMask(bdir.getFeaturesMask())) {
                message.append("<BR>Invalid Features Mask Value for Face Modality, expected values between[0x000000 and 0xFFFFFF], but received input value[").append(String.format("0x%06X", bdir.getFeaturesMask())).append("]");
                isValid = false;
            }

            if (!FaceISOStandardsValidator.getInstance().isValidFeatureMask(bdir.getExpressionMask())) {
                message.append("<BR>Invalid Expression Mask Value for Face Modality, expected values between[0x000000 and 0xFFFFFF], but received input value[").append(String.format("0x%06X", bdir.getExpressionMask())).append("]");
                isValid = false;
            }

            if (!FaceISOStandardsValidator.getInstance().isValidPoseAngle(bdir.getPoseAngle())) {
                message.append("<BR>Invalid Pose Angle Value for Face Modality");
                isValid = false;
            }

            if (!FaceISOStandardsValidator.getInstance().isValidPoseAngleUncertainty(bdir.getPoseAngleUncertainty())) {
                message.append("<BR>Invalid Pose Angle Uncertainty Value for Face Modality");
                isValid = false;
            }

            if (!FaceISOStandardsValidator.getInstance().isValidPoseAngleUncertainty(bdir.getPoseAngleUncertainty())) {
                message.append("<BR>Invalid Pose Angle Uncertainty Value for Face Modality");
                isValid = false;
            }

            // Future Implementation
            if (bdir.getNoOfLandMarkPoints() > 0) {
                for (LandmarkPoints landmarkPoints : bdir.getLandmarkPoints()) {
                    if (!FaceISOStandardsValidator.getInstance()
                            .isValidLandmarkPointType(landmarkPoints.getLandmarkPointType())) {
                        message.append("<BR>Invalid Landmark Point Type for Face Modality, expected values between[0x00 and 0xFF], but received input value[").append(String.format("0x%02X", landmarkPoints.getLandmarkPointType())).append("]");
                        isValid = false;
                    }

                    if (!FaceISOStandardsValidator.getInstance().isValidLandmarkPointCode(
                            landmarkPoints.getLandmarkPointType(), landmarkPoints.getLandmarkPointCode())) {
                        message.append("<BR>Invalid Landmark Point Code for Face Modality, expected values between[0x00 and 0xFF], but received input value[").append(String.format("0x%02X", landmarkPoints.getLandmarkPointCode())).append("]");
                        isValid = false;
                    }

                    if (!FaceISOStandardsValidator.getInstance().isValidLandmarkXCooridinate(
                            landmarkPoints.getLandmarkPointType(), landmarkPoints.getLandmarkPointCode(),
                            landmarkPoints.getXCoordinate())) {
                        message.append("<BR>Invalid Landmark X Cooridinate for Face Modality, expected values between[0x0000 and 0xFFFF], but received input value[").append(String.format("0x%04X", landmarkPoints.getXCoordinate())).append("]");
                        isValid = false;
                    }

                    if (!FaceISOStandardsValidator.getInstance().isValidLandmarkYCooridinate(
                            landmarkPoints.getLandmarkPointType(), landmarkPoints.getLandmarkPointCode(),
                            landmarkPoints.getYCoordinate())) {
                        message.append("<BR>Invalid Landmark Y Cooridinate for Face Modality, expected values between[0x0000 and 0xFFFF], but received input value[").append(String.format("0x%04X", landmarkPoints.getYCoordinate())).append("]");
                        isValid = false;
                    }

                    if (!FaceISOStandardsValidator.getInstance().isValidLandmarkZCooridinate(
                            landmarkPoints.getLandmarkPointType(), landmarkPoints.getLandmarkPointCode(),
                            landmarkPoints.getZCoordinate())) {
                        message.append("<BR>Invalid Landmark Z Cooridinate for Face Modality, expected values between[0x0000 and 0xFFFF], but received input value[").append(String.format("0x%04X", landmarkPoints.getZCoordinate())).append("]");
                        isValid = false;
                    }
                }
            }

            if (!FaceISOStandardsValidator.getInstance().isValidFaceImageType(bdir.getFaceImageType())) {
                message.append("<BR>Invalid Face Image Type Value for Face Modality, expected values between[{0x00 and 0x03}, {0x80 and 0x82}], but received input value[").append(String.format("0x%02X", bdir.getFaceImageType())).append("]");
                isValid = false;
            }

            int compressionType = bdir.getImageDataType();
            if (!(compressionType == ImageDataType.JPEG2000_LOSSY
                    || compressionType == ImageDataType.JPEG2000_LOSS_LESS)) {
                message.append("<BR>Invalid Image Compression Type for Finger Modality, expected values[JPEG_2000_LOSSY(0x01), JPEG_2000_LOSS_LESS(0x02)], but received input value[" + ", (").append(String.format("0x%02X", compressionType)).append(")]");
                isValid = false;
            }

            byte[] inImageData = bdir.getImage();

            if (!FaceISOStandardsValidator.getInstance()
                    .isValidSpatialSamplingRateLevel(bdir.getSpatialSamplingRateLevel())) {
                message.append("<BR>Invalid Spatial Sampling Rate Level Value for Face Modality, expected values between[0x00 and 0x07], but received input value[").append(String.format("0x%02X", bdir.getSpatialSamplingRateLevel())).append("]");
                isValid = false;
            }

            if (!FaceISOStandardsValidator.getInstance()
                    .isValidPostAcquisitionProcessing(bdir.getPostAcquistionProcessing())) {
                message.append("<BR>Invalid Post Acquisition Processing Value for Face Modality, expected values between[0x0000 and 0xFFFF], but received input value[").append(String.format("0x%02X", bdir.getPostAcquistionProcessing())).append("]");
                isValid = false;
            }

            if (!FaceISOStandardsValidator.getInstance().isValidCrossReference(bdir.getCrossReference())) {
                message.append("<BR>Invalid Cross Reference  Value for Face Modality, expected values between[0x00 and 0xFF], but received input value[").append(String.format("0x%02X", bdir.getCrossReference())).append("]");
                isValid = false;
            }

            if (!(bdir.getImageColorSpace() == ImageColourSpace.BIT_24_RGB)) {
                message.append("<BR>Invalid Image Bit Depth Value for Face Modality, expected values[0x01], but received input value[").append(String.format("0x%02X", bdir.getImageColorSpace())).append("]");
                isValid = false;
            }

            if (!FaceISOStandardsValidator.getInstance().isValidImageDataLength(inImageData, bdir.getImageLength())) {
                message.append("<BR>Invalid Image Data Length for Face Modality, expected values between[0x00000001 and 0xFFFFFFFF], but received input value[").append(String.format("0x%08X", bdir.getImageLength())).append("]");
                isValid = false;
            }

            // TODO check the condition: imagedata
            if (!isValid) {
                responseStatus = ResponseStatus.INVALID_INPUT;
                throw new SDKException(String.valueOf(responseStatus.getStatusCode()),
                        responseStatus.getStatusMessage() + " " + message.toString());
            }
            return true;
        } catch (Exception ex) {
            responseStatus = ResponseStatus.INVALID_INPUT;
            throw new SDKException(String.valueOf(responseStatus.getStatusCode()),
                    responseStatus.getStatusMessage() + " " + ex.getLocalizedMessage());
        }
    }

}
