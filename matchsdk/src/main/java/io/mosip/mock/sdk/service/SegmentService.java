package io.mosip.mock.sdk.service;

import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.mosip.kernel.biometrics.constant.BiometricType;
import io.mosip.kernel.biometrics.entities.BiometricRecord;
import io.mosip.kernel.biometrics.model.Response;
import io.mosip.mock.sdk.constant.ResponseStatus;
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
        Response<BiometricRecord> response = new Response<>();
        // do actual Segmentation
        response.setStatusCode(ResponseStatus.UNKNOWN_ERROR.getStatusCode());
        response.setStatusMessage(ResponseStatus.UNKNOWN_ERROR.getStatusMessage());
        response.setResponse(null);
        return response;
    }
}
