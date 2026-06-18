/*
 * Copyright (c) Modular Open Source Identity Platform
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */
package io.mosip.mock.sdk.exception;

import io.mosip.kernel.core.exception.BaseUncheckedException;

public class ConversionException extends BaseUncheckedException {
    private static final long serialVersionUID = 687991492884005033L;

    /**
     * Constructor the initialize Handler exception
     *
     * @param errorCode    The error code for this exception
     * @param errorMessage The error message for this exception
     */
    public ConversionException(String errorCode, String errorMessage) {
        super(errorCode, errorMessage);
    }

    /**
     * Constructor the initialize Handler exception
     *
     * @param errorCode    The error code for this exception
     * @param errorMessage The error message for this exception
     * @param rootCause    the specified cause
     */
    public ConversionException(String errorCode, String errorMessage, Throwable rootCause) {
        super(errorCode, errorMessage, rootCause);
    }
}
