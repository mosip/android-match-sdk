package io.mosip.registration.matchsdk.service;

import java.util.Map;

import io.mosip.registration.matchsdk.exception.ConversionException;

public interface IConverterApi {
    Map<String, String> convert(Map<String, String> values, String sourceFormat, String targetFormat, Map<String, String> sourceParameters, Map<String, String> targetParameters) throws ConversionException;
}
