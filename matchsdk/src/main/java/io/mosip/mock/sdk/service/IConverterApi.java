package io.mosip.mock.sdk.service;

import java.util.Map;

import io.mosip.mock.sdk.exception.ConversionException;

public interface IConverterApi {
    Map<String, String> convert(Map<String, String> values, String sourceFormat, String targetFormat, Map<String, String> sourceParameters, Map<String, String> targetParameters) throws ConversionException;
}
