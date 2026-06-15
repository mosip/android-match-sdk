package io.mosip.registration.matchsdk.constant;

import io.mosip.registration.matchsdk.exception.ConversionException;

public enum TargetFormatCode {
    IMAGE_JPEG("IMAGE/JPEG", "jpeg format"),
    IMAGE_PNG("IMAGE/PNG", "png format"),
    ISO19794_4_2011_JPEG("ISO19794_4_2011/JPEG", "Finger ISO format to Finger ISO format with JPEG IMAGE"),
    ISO19794_5_2011_JPEG("ISO19794_5_2011/JPEG", "Face ISO format to Finger ISO format with JPEG IMAGE"),
    //ISO19794_6_2011_JPEG("ISO19794_6_2011/JPEG", "Iris ISO format to Finger ISO format with JPEG IMAGE"),
    ISO19794_4_2011_PNG("ISO19794_4_2011/PNG", "Finger ISO format to Finger ISO format with PNG IMAGE"),
    ISO19794_5_2011_PNG("ISO19794_5_2011/PNG", "Face ISO format to Finger ISO format with PNG IMAGE"),
    ISO19794_6_2011_PNG("ISO19794_6_2011/PNG", "Iris ISO format to Finger ISO format with PNG IMAGE");

    private final String code;
    private final String message;

    private TargetFormatCode(final String code, final String message) {
        this.code = code;
        this.message = message;
    }

    public String getCode() {
        return code;
    }

    public static TargetFormatCode fromCode(String targetCodeName) {
        for (TargetFormatCode targetCode : TargetFormatCode.values()) {
            if (targetCode.getCode().equalsIgnoreCase(targetCodeName)) {
                return targetCode;
            }
        }
        throw new ConversionException(ConverterErrorCode.INVALID_TARGET_EXCEPTION.getErrorCode(), ConverterErrorCode.INVALID_TARGET_EXCEPTION.getErrorMessage());
    }

    public static boolean validCode(String targetCodeName) {
        for (TargetFormatCode targetCode : TargetFormatCode.values()) {
            if (targetCode.getCode().equalsIgnoreCase(targetCodeName)) {
                return true;
            }
        }
        return false;
    }

    public String getMessage() {
        return message;
    }

    @Override
    public String toString() {
        return getCode();
    }
}
