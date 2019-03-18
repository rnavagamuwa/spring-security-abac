package org.wso2.spring.security.abac.exception;

/**
 * @author Randika Navagamuwa
 */
public class AttributeEvaluatorException extends RuntimeException {

    public AttributeEvaluatorException(String message) {

        super(message);
    }

    public AttributeEvaluatorException(String message, Throwable cause) {

        super(message, cause);
    }
}
