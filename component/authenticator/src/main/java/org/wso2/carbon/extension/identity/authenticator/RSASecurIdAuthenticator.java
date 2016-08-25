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
 */
package org.wso2.carbon.extension.identity.authenticator;

import com.rsa.authagent.authapi.AuthAgentException;
import com.rsa.authagent.authapi.AuthSession;
import com.rsa.authagent.authapi.AuthSessionFactory;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.CarbonUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;

/**
 * RSA SecurId 2-Factor Authenticator
 */
public class RSASecurIdAuthenticator extends AbstractApplicationAuthenticator
        implements LocalApplicationAuthenticator {

    private static Log log = LogFactory.getLog(RSASecurIdAuthenticator.class);

    /**
     * Get the friendly name of the RSA SecurID Authenticator
     *
     * @return RSA SecurId Authenticator Friendly Name
     */
    @Override
    public String getFriendlyName() {
        return RSASecurIdAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * Check authentication request can be handled or not.
     *
     * @param request http servlet request to the authenticator
     * @return TRUE if RSA_USER_PASSCODE exists otherwise FALSE
     */
    @Override
    public boolean canHandle(HttpServletRequest request) {
        if (log.isDebugEnabled()) {
            log.debug("Inside RSA SecurId Authenticator canHandle()");
        }
        String passCode = request.getParameter(RSASecurIdAuthenticatorConstants.RSA_USER_PASSCODE);
        if (StringUtils.isNotEmpty(passCode)) {
            return true;
        }
        return false;
    }

    /**
     * Allowing user for retrying another attempt
     *
     * @return TRUE or FALSE
     */
    protected boolean retryAuthenticationEnabled() {
        return true;
    }

    /**
     * Initiating th authentication request to RSA Authenticator
     *
     * @param request               http servlet request to the authentication framework
     * @param response              http servlet response from authentication framework
     * @param authenticationContext authenticationContext contains information about authentication
     *                              flow
     * @throws AuthenticationFailedException Throwing the authenticationFailedException
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext authenticationContext)
            throws AuthenticationFailedException {
        if (log.isDebugEnabled()) {
            log.debug("Inside the initiateAuthenticationRequest of RSA SecurID Authenticator");
        }
        String rsaLoginPage;
        String retryParam = "";

        try {
            if (authenticationContext.isRetrying()) {
                if (log.isDebugEnabled()) {
                    log.debug("Retrying is enabled for RSA SecurID Authenticator");
                }
                retryParam = RSASecurIdAuthenticatorConstants.RETRY_PARAMS;
            }
            rsaLoginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                    .replace("authenticationendpoint/login.do", RSASecurIdAuthenticatorConstants.LOGIN_ENDPOINT);
            String queryParams = FrameworkUtils
                    .getQueryStringWithFrameworkContextId(authenticationContext.getQueryParams(),
                            authenticationContext.getCallerSessionKey(),
                            authenticationContext.getContextIdentifier());
            response.sendRedirect(response.encodeRedirectURL(rsaLoginPage
                    + "?" + queryParams + retryParam));
        } catch (IOException e) {
            throw new AuthenticationFailedException("RSA SecurId Authenticator could not handle the inputs " +
                    "and outputs", e);
        }
    }

    /**
     * Get the previously authenticated local user
     *
     * @param authenticationContext authenticationContext contains information about authentication
     * @return authenticatedUser information
     */
    private AuthenticatedUser getUsername(AuthenticationContext authenticationContext) {
        AuthenticatedUser authenticatedUser = null;
        for (int i = 1; i <= authenticationContext.getSequenceConfig().getStepMap().size(); i++) {
            StepConfig stepConfig = authenticationContext.getSequenceConfig().getStepMap().get(i);
            if (stepConfig.getAuthenticatedUser() != null && stepConfig.getAuthenticatedAutenticator()
                    .getApplicationAuthenticator() instanceof LocalApplicationAuthenticator) {
                authenticatedUser = stepConfig.getAuthenticatedUser();
                break;
            }
        }
        return authenticatedUser;
    }

    /**
     * Get the context identifier of authentication flow
     *
     * @param request http servlet request to the authentication framework
     * @return sessionDataKey
     */
    @Override
    public String getContextIdentifier(HttpServletRequest request) {
        return request.getParameter(FrameworkConstants.SESSION_DATA_KEY);
    }

    /**
     * Get the name of the RSA SecurId authenticator
     *
     * @return name of the authenticator
     */
    @Override
    public String getName() {
        return RSASecurIdAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    /**
     * Processing and validating the authentication
     *
     * @param request               http servlet request to the authentication framework
     * @param response              http servlet response from the authentication framework
     * @param authenticationContext authenticationContext contains information about authentication
     *                              flow
     * @throws AuthenticationFailedException
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext authenticationContext)
            throws AuthenticationFailedException {
        int authStatus;
        AuthenticatedUser authenticatedUser = getUsername(authenticationContext);
        String username = authenticatedUser.getAuthenticatedSubjectIdentifier();
        String tenantDomain = authenticatedUser.getTenantDomain();
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        RealmService realmService = IdentityTenantUtil.getRealmService();
        UserRealm userRealm;
        String rsaUserId;
        try {
            userRealm = realmService.getTenantUserRealm(tenantId);
            rsaUserId = userRealm.getUserStoreManager()
                    .getUserClaimValue(username, RSASecurIdAuthenticatorConstants.RSASecurId_CLAIM, null);
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("Error occurred while loading user realm or user store manager : ",
                    e);
        }

        String passCode = request.getParameter(RSASecurIdAuthenticatorConstants.RSA_USER_PASSCODE);
        AuthSessionFactory authSessionFactory = null;
        if (StringUtils.isNotEmpty(rsaUserId) && StringUtils.isNotEmpty(passCode)) {
            AuthSession session = null;
            try {
                String configPath = CarbonUtils.getCarbonConfigDirPath() + File.separator
                        + RSASecurIdAuthenticatorConstants.IDENTITY_CLAIM + File.separator;
                configPath = configPath + RSASecurIdAuthenticatorConstants.RSA_PROPERTIES_FILE;
                authSessionFactory = AuthSessionFactory.getInstance(configPath);
                session = authSessionFactory.createUserSession();
                session.lock(rsaUserId);
                authStatus = session.check(rsaUserId, passCode);
                if (authStatus == AuthSession.ACCESS_OK) {
                    authenticationContext.setSubject(authenticatedUser);
                } else {
                    throw new AuthenticationFailedException("User enters invalid pass code");
                }
            } catch (AuthAgentException e) {
                throw new AuthenticationFailedException("Authentication Agent failed to create connection to " +
                        "authSessionFactory", e);
            } finally {
                if (authSessionFactory != null)
                    try {
                        session.close();
                        authSessionFactory.shutdown();

                    } catch (AuthAgentException e) {
                        throw new AuthenticationFailedException("Could not able to shutdown the API", e);
                    }
            }
        } else {
            throw new AuthenticationFailedException("Pass code is Empty");
        }
    }
}