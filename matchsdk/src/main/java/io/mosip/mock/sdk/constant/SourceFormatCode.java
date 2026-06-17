/*
 * Copyright (c) Modular Open Source Identity Platform
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */
package io.mosip.mock.sdk.constant;

import io.mosip.mock.sdk.exception.ConversionException;

public enum SourceFormatCode {
    ISO19794_4_2011("ISO19794_4_2011", "Finger ISO format"),
    ISO19794_5_2011("ISO19794_5_2011", "Face ISO format"),
    ISO19794_6_2011("ISO19794_6_2011", "Iris ISO format");

    private final String code;
    private final String message;

    private SourceFormatCode(final String code, final String message) {
        this.code = code;
        this.message = message;
    }

    public String getCode() {
        return code;
    }

    public static SourceFormatCode fromCode(String sourceCodeName) {
        for (SourceFormatCode sourceCode : SourceFormatCode.values()) {
            if (sourceCode.getCode().equalsIgnoreCase(sourceCodeName)) {
                return sourceCode;
            }
        }
        throw new ConversionException(ConverterErrorCode.INVALID_SOURCE_EXCEPTION.getErrorCode(), ConverterErrorCode.INVALID_SOURCE_EXCEPTION.getErrorMessage());
    }

    public static boolean validCode(String sourceCodeName) {
        for (SourceFormatCode sourceCode : SourceFormatCode.values()) {
            if (sourceCode.getCode().equalsIgnoreCase(sourceCodeName)) {
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
