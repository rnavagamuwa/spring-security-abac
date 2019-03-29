package com.rnavagamuwa.springsecurity.stereotypes;

import java.lang.annotation.*;

/**
 * @author Randika Navagamuwa
 */
@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface CurrentUser {}
