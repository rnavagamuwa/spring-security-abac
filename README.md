# XACML based authorization for Spring security

Even though spring security provides role-based access control it doesn’t allow users to perform policy-based authorization. The main goal of this project is to write an agent which can be used to perform attribute-based access control for Spring security. 

Spring security provides an annotation for custom authorization evaluations.

As the initial version, I have managed to write a working sample for this use case. This sample talks to WSO2 PDP for authorization.