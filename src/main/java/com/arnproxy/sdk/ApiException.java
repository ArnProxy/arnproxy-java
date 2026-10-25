package com.arnproxy.sdk;

/** Safe metadata only. Never includes an API key, raw response or cause. */
public final class ApiException extends RuntimeException {
    public final String code;
    public final Integer httpStatus;
    public final String requestId;
    public final Integer retryAfter;
    public final boolean uncertain;
    ApiException(String code) { this(code,null,null,null,false); }
    ApiException(String code,Integer status,String requestId,Integer retryAfter,boolean uncertain) {
        super(code,null,false,false);this.code=code;this.httpStatus=status;
        this.requestId=requestId;this.retryAfter=retryAfter;this.uncertain=uncertain;
    }
}
