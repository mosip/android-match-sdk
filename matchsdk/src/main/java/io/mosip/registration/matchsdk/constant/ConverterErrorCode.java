package io.mosip.registration.matchsdk.constant;

public enum ConverterErrorCode {
    INPUT_SOURCE_EXCEPTION("MOS-CNV-001", "Input Source Request may be null or Source Format may be null or Target Format may be null"),
    INVALID_REQUEST_EXCEPTION("MOS-CNV-002", "Invalid Request Value"),
    INVALID_SOURCE_EXCEPTION("MOS-CNV-003", "Invalid Source Value or Source Format not supported[ex:\"ISO19794_4_2011\", \"ISO19794_5_2011\", \"ISO19794_6_2011\"]"),
    INVALID_TARGET_EXCEPTION("MOS-CNV-004", "Invalid Target Value or Target Format not supported[ex:\"IMAGE/JPEG\", \"IMAGE/PNG\"]"),
    SOURCE_CAN_NOT_BE_EMPTY_OR_NULL_EXCEPTION("MOS-CNV-005", "Source value can not be empty or null"),
    SOURCE_NOT_VALID_BASE64URLENCODED_EXCEPTION("MOS-CNV-006", "Source not valid base64urlencoded"),
    COULD_NOT_READ_ISO_IMAGE_DATA_EXCEPTION("MOS-CNV-007", "Could not read Source ISO Image Data"),
    SOURCE_NOT_VALID_FINGER_ISO_FORMAT_EXCEPTION("MOS-CNV-008", "Source not valid ISO ISO19794_4_2011"),
    SOURCE_NOT_VALID_FACE_ISO_FORMAT_EXCEPTION("MOS-CNV-009", "Source not valid ISO ISO19794_5_2011"),
    SOURCE_NOT_VALID_IRIS_ISO_FORMAT_EXCEPTION("MOS-CNV-010", "Source not valid ISO ISO19794_6_2011"),
    TARGET_FORMAT_EXCEPTION("MOS-CNV-011", "Target Format(ISO19794_6_2011_JPEG) Not Supported For the Given Source Format(ISO19794_6_2011)"),
    NOT_SUPPORTED_COMPRESSION_TYPE("MOS-CNV-012", "Not Supported Compression Type"),

    TECHNICAL_ERROR_EXCEPTION("MOS-CNV-500", "Technical Error");

    private final String errorCode;
    private final String errorMessage;

    private ConverterErrorCode(final String errorCode, final String errorMessage) {
        this.errorCode = errorCode;
        this.errorMessage = errorMessage;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public static ConverterErrorCode fromErrorCode(String errorCode) {
        for (ConverterErrorCode paramCode : ConverterErrorCode.values()) {
            if (paramCode.getErrorCode().equalsIgnoreCase(errorCode)) {
                return paramCode;
            }
        }
        return TECHNICAL_ERROR_EXCEPTION;
    }
}
