package com.moxtra.util;

import org.apache.commons.lang.exception.NestableException; 

/**
 * @author jmi
 */
public class MoxtraAPIUtilException extends NestableException {
    private static final long serialVersionUID = -866497531917758585L;
    
    public MoxtraAPIUtilException(String message) {
        super(message);
    }
    public MoxtraAPIUtilException(String message, Throwable t) {
        super(message, t);
    }

}
