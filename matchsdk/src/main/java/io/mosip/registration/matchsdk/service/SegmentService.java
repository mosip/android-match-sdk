package io.mosip.registration.matchsdk.service;

import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.mosip.kernel.biometrics.constant.BiometricType;
import io.mosip.kernel.biometrics.entities.BiometricRecord;
import io.mosip.kernel.biometrics.model.Response;
public class SegmentService extends SDKService{
    private Logger LOGGER = LoggerFactory.getLogger(SegmentService.class);

    private BiometricRecord sample;
    private List<BiometricType> modalitiesToSegment;

    public SegmentService(BiometricRecord sample, List<BiometricType> modalitiesToSegment,
                          Map<String, String> flags) {
        super(flags);
        this.sample = sample;
        this.modalitiesToSegment = modalitiesToSegment;
    }

    public Response<BiometricRecord> getSegmentInfo() {
        BiometricRecord record = new BiometricRecord();
        record.setSegments(null);
        Response<BiometricRecord> response = new Response<>();
        // do actual Segmentation
        response.setStatusCode(200);
        response.setResponse(record);
        return response;
    }
}
