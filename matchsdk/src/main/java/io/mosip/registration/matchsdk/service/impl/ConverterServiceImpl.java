package io.mosip.registration.matchsdk.service.impl;

import static io.mosip.registration.matchsdk.constant.ConverterErrorCode.INVALID_TARGET_EXCEPTION;
import static io.mosip.registration.matchsdk.constant.ConverterErrorCode.NOT_SUPPORTED_COMPRESSION_TYPE;

import android.graphics.BitmapFactory;
import android.graphics.Color;

import org.jnbis.api.model.Bitmap;
import org.jnbis.internal.WsqDecoder;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;

import io.mosip.biometrics.util.CommonUtil;
import io.mosip.biometrics.util.ConvertRequestDto;
import io.mosip.biometrics.util.face.FaceBDIR;
import io.mosip.biometrics.util.face.FaceDecoder;
import io.mosip.biometrics.util.face.ImageDataType;
import io.mosip.biometrics.util.finger.FingerBDIR;
import io.mosip.biometrics.util.finger.FingerDecoder;
import io.mosip.biometrics.util.finger.FingerImageCompressionType;
import io.mosip.biometrics.util.iris.ImageFormat;
import io.mosip.biometrics.util.iris.IrisBDIR;
import io.mosip.biometrics.util.iris.IrisDecoder;
import io.mosip.registration.matchsdk.constant.ConverterErrorCode;
import io.mosip.registration.matchsdk.constant.SourceFormatCode;
import io.mosip.registration.matchsdk.constant.TargetFormatCode;
import io.mosip.registration.matchsdk.exception.ConversionException;
import io.mosip.registration.matchsdk.service.IConverterApi;

public class ConverterServiceImpl implements IConverterApi {

    @Override
    public Map<String, String> convert(Map<String, String> values, String sourceFormat, String targetFormat, Map<String, String> sourceParameters, Map<String, String> targetParameters) throws ConversionException {
        ConverterErrorCode errorCode = null;
        Map<String, String> targetValues = new HashMap<String, String>();

        SourceFormatCode sourceCode = SourceFormatCode.fromCode(sourceFormat);
        TargetFormatCode targetCode = TargetFormatCode.fromCode(targetFormat);
        for (Map.Entry<String,String> entry : values.entrySet())
        {
            String targetValue = null;
            String isoData = entry.getValue();
            if (isoData == null || isoData.trim ().length () == 0)
            {
                errorCode = ConverterErrorCode.SOURCE_CAN_NOT_BE_EMPTY_OR_NULL_EXCEPTION;
                throw new ConversionException (errorCode.getErrorCode(), errorCode.getErrorMessage ());
            }

            switch (sourceCode)
            {
                // FINGER ISO can have JP2000 or WSQ
                case ISO19794_4_2011:
                    targetValue = convertFingerIsoToImageType(sourceCode, entry.getValue(), targetCode, targetParameters);
                    break;
                // FACE ISO can have JP2000
                case ISO19794_5_2011:
                    targetValue = convertFaceIsoToImageType(sourceCode, entry.getValue(), targetCode, targetParameters);
                    break;
                // IRIS ISO can have JP2000
                case ISO19794_6_2011:
                    targetValue = convertIrisIsoToImageType(sourceCode, entry.getValue(), targetCode, targetParameters);
                    break;
                default:
                    errorCode = ConverterErrorCode.INVALID_SOURCE_EXCEPTION;
                    throw new ConversionException (errorCode.getErrorCode(), errorCode.getErrorMessage());
            }
            targetValues.put(entry.getKey(), targetValue);
        }
        return targetValues;
    }

    private String convertFingerIsoToImageType(SourceFormatCode sourceCode, String isoData, TargetFormatCode targetCode,
                                               Map<String, String> targetParameters) throws ConversionException {
        ConverterErrorCode errorCode = ConverterErrorCode.TECHNICAL_ERROR_EXCEPTION;

        ConvertRequestDto requestDto = new ConvertRequestDto();
        requestDto.setModality("Finger");
        requestDto.setVersion(sourceCode.getCode());

        try {
            requestDto.setInputBytes(CommonUtil.decodeURLSafeBase64 (isoData));
        } catch (Exception e) {
            errorCode = ConverterErrorCode.SOURCE_NOT_VALID_BASE64URLENCODED_EXCEPTION;
            throw new ConversionException (errorCode.getErrorCode(), e.getLocalizedMessage());
        }

        FingerBDIR bdir;
        int inCompressionType = -1;
        byte [] inImageData = null;
        try {
            bdir = FingerDecoder.getFingerBDIR(requestDto);

            inCompressionType = bdir.getCompressionType();
            inImageData = bdir.getImage();
        } catch (Exception e) {
            errorCode = ConverterErrorCode.SOURCE_NOT_VALID_FINGER_ISO_FORMAT_EXCEPTION;
            throw new ConversionException (errorCode.getErrorCode(), e.getLocalizedMessage());
        }

        android.graphics.Bitmap outImage;
        byte [] outImageData;
        switch(inCompressionType)
        {
            case FingerImageCompressionType.JPEG_2000_LOSSY:
            case FingerImageCompressionType.JPEG_2000_LOSS_LESS:
                try {
                    outImage = BitmapFactory.decodeByteArray(inImageData, 0, inImageData.length);
                    // change here outImage width, height, dpi here based on targetParameters
                } catch (Exception e) {
                    errorCode = ConverterErrorCode.COULD_NOT_READ_ISO_IMAGE_DATA_EXCEPTION;
                    throw new ConversionException (errorCode.getErrorCode(), e.getLocalizedMessage());
                }
                outImageData = convertBufferedImageToBytes(targetCode, outImage);
                break;
            case FingerImageCompressionType.WSQ:
                WsqDecoder decoder = new WsqDecoder ();
                Bitmap wsqBitmap = decoder.decode(inImageData);

                int wsqBitmapWidth = wsqBitmap.getWidth();
                int wsqBitmapHeight = wsqBitmap.getHeight();
                byte[] wsqBitmapPixels = wsqBitmap.getPixels();
                //android way of converting to gray scale bitmap image
                for (int i = 0; i < wsqBitmapPixels.length; i++) {
                    int pixel = wsqBitmapPixels[i];
                    int gray = (int) (Color.red(pixel) * 0.299 + Color.green(pixel) * 0.587 + Color.blue(pixel) * 0.114);
                    wsqBitmapPixels[i] = (byte) gray;
                }
                android.graphics.Bitmap grayscaleBitmap = android.graphics.Bitmap.createBitmap(wsqBitmapWidth,
                        wsqBitmapHeight, android.graphics.Bitmap.Config.ALPHA_8);
                grayscaleBitmap.copyPixelsFromBuffer(ByteBuffer.wrap(wsqBitmapPixels));

               // outImage = CommonUtil.convert(bitmap);
                // change here outImage width, height, dpi here based on targetParameters
                outImageData = convertBufferedImageToBytes(targetCode, grayscaleBitmap);
                break;
            default:
                throw new ConversionException (NOT_SUPPORTED_COMPRESSION_TYPE.getErrorCode(), NOT_SUPPORTED_COMPRESSION_TYPE.getErrorMessage());
        }
        return CommonUtil.encodeToURLSafeBase64(outImageData);
    }

    private String convertFaceIsoToImageType(SourceFormatCode sourceCode, String isoData, TargetFormatCode targetCode,
                                             Map<String, String> targetParameters) throws ConversionException {
        ConverterErrorCode errorCode = ConverterErrorCode.TECHNICAL_ERROR_EXCEPTION;

        ConvertRequestDto requestDto = new ConvertRequestDto();
        requestDto.setModality("Face");
        requestDto.setVersion(sourceCode.getCode());
        try {
            requestDto.setInputBytes(CommonUtil.decodeURLSafeBase64 (isoData));
        } catch (Exception e) {
            errorCode = ConverterErrorCode.SOURCE_NOT_VALID_BASE64URLENCODED_EXCEPTION;
            throw new ConversionException (errorCode.getErrorCode(), e.getLocalizedMessage());
        }

        FaceBDIR bdir;
        int inImageDataType = -1;
        byte [] inImageData;
        try {
            bdir = FaceDecoder.getFaceBDIR(requestDto);

            inImageDataType = bdir.getImageDataType();
            inImageData = bdir.getImage();
        } catch (Exception e) {
            errorCode = ConverterErrorCode.SOURCE_NOT_VALID_FACE_ISO_FORMAT_EXCEPTION;
            throw new ConversionException (errorCode.getErrorCode(), e.getLocalizedMessage());
        }

        android.graphics.Bitmap outImage;
        byte [] outImageData;
        switch(inImageDataType)
        {
            case ImageDataType.JPEG2000_LOSSY:
            case ImageDataType.JPEG2000_LOSS_LESS:
                try {
                    outImage = BitmapFactory.decodeByteArray(inImageData, 0, inImageData.length);
                    // change here outImage width, height, dpi here based on targetParameters
                } catch (Exception e) {
                    errorCode = ConverterErrorCode.COULD_NOT_READ_ISO_IMAGE_DATA_EXCEPTION;
                    throw new ConversionException (errorCode.getErrorCode(), e.getLocalizedMessage());
                }
                outImageData = convertBufferedImageToBytes(targetCode, outImage);
                break;
            default:
                throw new ConversionException (NOT_SUPPORTED_COMPRESSION_TYPE.getErrorCode(), NOT_SUPPORTED_COMPRESSION_TYPE.getErrorMessage());
        }
        return CommonUtil.encodeToURLSafeBase64(outImageData);
    }

    private String convertIrisIsoToImageType(SourceFormatCode sourceCode, String isoData, TargetFormatCode targetCode,
                                             Map<String, String> targetParameters) throws ConversionException {
        ConverterErrorCode errorCode = ConverterErrorCode.TECHNICAL_ERROR_EXCEPTION;

        ConvertRequestDto requestDto = new ConvertRequestDto();
        requestDto.setModality("Iris");
        requestDto.setVersion(sourceCode.getCode());
        try {
            requestDto.setInputBytes(CommonUtil.decodeURLSafeBase64 (isoData));
        } catch (Exception e) {
            errorCode = ConverterErrorCode.SOURCE_NOT_VALID_BASE64URLENCODED_EXCEPTION;
            throw new ConversionException (errorCode.getErrorCode(), e.getLocalizedMessage());
        }

        int inImageFormat = -1;
        byte [] inImageData;
        IrisBDIR bdir;
        try {
            bdir = IrisDecoder.getIrisBDIR(requestDto);
            inImageFormat = bdir.getImageFormat();
            inImageData = bdir.getImage();
        } catch (Exception e) {
            errorCode = ConverterErrorCode.SOURCE_NOT_VALID_IRIS_ISO_FORMAT_EXCEPTION;
            throw new ConversionException (errorCode.getErrorCode(), e.getLocalizedMessage());
        }
        android.graphics.Bitmap bitmap;
        byte [] outImageData;
        if (inImageFormat == ImageFormat.MONO_JPEG2000) {
            try {
                // outImage = ImageIO.read(new ByteArrayInputStream(inImageData));
                bitmap = BitmapFactory.decodeByteArray(inImageData, 0, inImageData.length);
                // change here outImage width, height, dpi here based on targetParameters
            } catch (Exception e) {
                errorCode = ConverterErrorCode.COULD_NOT_READ_ISO_IMAGE_DATA_EXCEPTION;
                throw new ConversionException(errorCode.getErrorCode(), e.getLocalizedMessage());
            }
            outImageData = convertBufferedImageToBytes(targetCode, bitmap);
        } else {
            throw new ConversionException(NOT_SUPPORTED_COMPRESSION_TYPE.getErrorCode(), NOT_SUPPORTED_COMPRESSION_TYPE.getErrorMessage());
        }
        return CommonUtil.encodeToURLSafeBase64(outImageData);
    }

    private byte[] convertBufferedImageToBytes(TargetFormatCode targetCode, android.graphics.Bitmap bitmap) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        switch (targetCode)
        {
            case IMAGE_JPEG:
                bitmap.compress( android.graphics.Bitmap.CompressFormat.JPEG, 100, outputStream);
                return outputStream.toByteArray();
            case IMAGE_PNG:
                bitmap.compress( android.graphics.Bitmap.CompressFormat.PNG, 100, outputStream);
                return outputStream.toByteArray();
            default:
                throw new ConversionException (INVALID_TARGET_EXCEPTION.getErrorCode(), INVALID_TARGET_EXCEPTION.getErrorMessage ());
        }
    }
}
