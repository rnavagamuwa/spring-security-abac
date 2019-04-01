package org.wso2.spring.security.abac.util;

import javax.servlet.http.Cookie;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Randika Navagamuwa
 */
class GeneralUtils {

    static Map<String, String> extractValuesFromCookies(Cookie[] cookies) {
        final Map<String, String> cookieValues = new HashMap<>();

        for (Cookie currentCookie : cookies) {
            cookieValues.put(currentCookie.getName(), currentCookie.getValue());
        }
        return cookieValues;
    }
}
