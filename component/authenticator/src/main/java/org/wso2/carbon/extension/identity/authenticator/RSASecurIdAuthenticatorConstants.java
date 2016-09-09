/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.wso2.carbon.extension.identity.authenticator;
public class RSASecurIdAuthenticatorConstants {
    public static final String AUTHENTICATOR_NAME = "RSASecurId";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "RSASecurIdAuthenticator";
    public static final String RSASecurId_CLAIM = "http://wso2.org/claims/identity/rsaUserId";
    public static final String LOGIN_PAGE = "authenticationendpoint/login.do";
    public static final String RSA_USER_TOKEN = "code";
    public static final String RETRY_PARAMS = "&authFailure=true&authFailureMsg=RSA+Login+Failed";
    public static final String RSA_USER_PIN = "pin";
    public static final String RSASECURID_AUTHENTICATION_ENDPOINT_URL = "RSASECURIDAuthenticationEndpointURL";
    public static final String RSASECURID_PROPERTY_FILE = "RSASECURIDPropertyFile";
}
