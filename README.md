# XACML based authorization for Spring security

### Overview

Even though spring security provides role-based access control it doesn’t allow users to perform policy-based authorization. The main goal of this project is to write an agent which can be used to perform attribute-based access control for Spring security. 

### Implementation

Spring security provides an annotation for custom authorization evaluations.

As the initial version, I have managed to write a working sample for this use case. This sample talks to WSO2 PDP for authorization.

#### The high-level sequence diagram


![](https://i.imgur.com/CUBbSxB.png)


#### Usage

1. Create a `keystore` and a `trustStore` in *Resources* directory.
2. Create a file named `xacmlConfig.json` in *Resources* directory. This file contains the body of the XACML request.
     * This file is a json file and this can have more than one *Target Domain Objects*. In this case let's define our target domain object as **admin_xacml**.
     * All the variables should start with **'$'**. For example if **action-id** is the variable it should be defined in the `xacmlConfig.sjon` as **$action-id**.
     
     A sample `xacmlConfig.json` file is as follows.
     ````
     {
       "admin_xacml": {
         "Request": {
           "Action": {
             "Attribute": [
               {
                 "AttributeId": "urn:oasis:names:tc:xacml:1.0:action:action-id",
                 "Value": "$action-id"
               }
             ]
           },
           "Resource": {
             "Attribute": [
               {
                 "AttributeId": "urn:oasis:names:tc:xacml:1.0:resource:resource-id",
                 "Value": "$resource-id"
               }
             ]
           }
         }
       }
     }
     ````
          
3. Extend `GlobalMethodSecurityConfiguration` class and set `AttributeEvaluator` as the new `PermissionEvaluator`
    ```
    @Configuration
    @EnableGlobalMethodSecurity(prePostEnabled = true)
    public class MethodSecurityConfig extends GlobalMethodSecurityConfiguration {
    
        @Override
        protected MethodSecurityExpressionHandler createExpressionHandler() {
    
            DefaultMethodSecurityExpressionHandler expressionHandler =
                    new DefaultMethodSecurityExpressionHandler();
            expressionHandler.setPermissionEvaluator(new AttributeEvaluator());
            return expressionHandler;
        }
    }
    ```
4. Now add the `@PreAuthorize("hasPermission()")` or `@PostAuthorize("hasPermission()")` annotation as required before the correct controller method. *Target Domain Object* and the *Permissions* should be passed to this annotaion as parameters.*Permissions* is a json object which contains the key value pairs. These permission values will be extracted from the *headers*. 
    
   ```
    @PreAuthorize("hasPermission('admin_xacml','{$action-id:action-id,$resource-id:resource-id}')")
    ```

