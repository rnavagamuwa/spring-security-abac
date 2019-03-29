package com.rnavagamuwa.springsecurity;

import com.rnavagamuwa.springsecurity.stereotypes.CurrentUser;
import org.springframework.core.MethodParameter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebArgumentResolver;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import java.security.Principal;

/**
 * @author Randika Navagamuwa
 */
@Component
public class CurrentUserHandlerMethodArgumentResolver implements
        HandlerMethodArgumentResolver {

    public boolean supportsParameter(MethodParameter methodParameter) {
        return methodParameter.getParameterAnnotation(CurrentUser.class) != null
                && methodParameter.getParameterType().equals(User.class);
    }

    public Object resolveArgument(MethodParameter methodParameter,
                                  ModelAndViewContainer mavContainer, NativeWebRequest webRequest,
                                  WebDataBinderFactory binderFactory) throws Exception {
        if (this.supportsParameter(methodParameter)) {
            Principal principal = (Principal) webRequest.getUserPrincipal();
            return (User) ((Authentication) principal).getPrincipal();
        } else {
            return WebArgumentResolver.UNRESOLVED;
        }
    }
}