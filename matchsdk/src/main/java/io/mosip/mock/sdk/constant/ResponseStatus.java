/*
 * Copyright (c) Modular Open Source Identity Platform
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */
package io.mosip.mock.sdk.constant;

public enum ResponseStatus {
    SUCCESS(200, "OK"),
    INVALID_INPUT(401, "Invalid Input Parameter"),
    MISSING_INPUT(402, "Missing Input Parameter"),
    QUALITY_CHECK_FAILED(403, "Quality check of Biometric data failed"),
    BIOMETRIC_NOT_FOUND_IN_CBEFF(404, "Biometrics not found in CBEFF"),
    MATCHING_OF_BIOMETRIC_DATA_FAILED(405, "Matching of Biometric data failed"),
    POOR_DATA_QUALITY(406, "Data provided is of poor quality"),
    UNKNOWN_ERROR(500, "UNKNOWN_ERROR");

    ResponseStatus(int statusCode, String statusMessage) {
        this.statusCode = statusCode;
        this.statusMessage = statusMessage;
    }

    private final int statusCode;
    private final String statusMessage;

    public int getStatusCode() {
        return statusCode;
    }

    public String getStatusMessage() {
        return statusMessage;
    }

    public static ResponseStatus fromStatusCode(int code) {
        for (ResponseStatus paramCode : ResponseStatus.values()) {
            if (paramCode.getStatusCode() == code) {
                return paramCode;
            }
        }
        return UNKNOWN_ERROR;
    }
}
