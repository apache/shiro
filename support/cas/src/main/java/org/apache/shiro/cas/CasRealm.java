/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.cas;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.util.CollectionUtils;
import org.apache.shiro.util.StringUtils;
import org.jasig.cas.client.authentication.AttributePrincipal;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.Cas20ServiceTicketValidator;
import org.jasig.cas.client.validation.Saml11TicketValidator;
import org.jasig.cas.client.validation.TicketValidationException;
import org.jasig.cas.client.validation.TicketValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * This realm implementation acts as a CAS client to a CAS server for authentication and basic authorization.
 * <p/>
 * This realm functions by inspecting a submitted {@link org.apache.shiro.cas.CasToken CasToken} (which essentially 
 * wraps a CAS service ticket) and validates it against the CAS server using a configured CAS
 * {@link org.jasig.cas.client.validation.TicketValidator TicketValidator}.
 * <p/>
 * The {@link #getValidationProtocol() validationProtocol} is {@code CAS} by default, which indicates that a
 * a {@link org.jasig.cas.client.validation.Cas20ServiceTicketValidator Cas20ServiceTicketValidator}
 * will be used for ticket validation.  You can alternatively set
 * or {@link org.jasig.cas.client.validation.Saml11TicketValidator Saml11TicketValidator} of CAS client. It is based on
 * {@link AuthorizingRealm AuthorizingRealm} for both authentication and authorization. User id and attributes are retrieved from the CAS
 * service ticket validation response during authentication phase. Roles and permissions are computed during authorization phase (according
 * to the attributes previously retrieved).
 *
 * @since 1.2
 * @deprecated since 2.0 if favor of the {@link org.apache.shiro.realm.AccountStoreRealm} configured with an CAS-specific {@link org.apache.shiro.account.AccountStore AccountStore}.
 */
@Deprecated
public class CasRealm extends AuthorizingRealm {

    // default name of the CAS attribute for remember me authentication (CAS 3.4.10+)
    public static final String DEFAULT_REMEMBER_ME_ATTRIBUTE_NAME = "longTermAuthenticationRequestTokenUsed";
    public static final String DEFAULT_VALIDATION_PROTOCOL = "CAS";
    
    private static Logger log = LoggerFactory.getLogger(CasRealm.class);
    
    // this is the url of the CAS server (example : http://host:port/cas)
    private String casServerUrlPrefix;
    
    // this is the CAS service url of the application (example : http://host:port/mycontextpath/shiro-cas)
    private String casService;
    
    /* CAS protocol to use for ticket validation : CAS (default) or SAML :
       - CAS protocol can be used with CAS server version < 3.1 : in this case, no user attributes can be retrieved from the CAS ticket validation response (except if there are some customizations on CAS server side)
       - SAML protocol can be used with CAS server version >= 3.1 : in this case, user attributes can be extracted from the CAS ticket validation response
    */
    private String validationProtocol = DEFAULT_VALIDATION_PROTOCOL;
    
    // default name of the CAS attribute for remember me authentication (CAS 3.4.10+)
    private String rememberMeAttributeName = DEFAULT_REMEMBER_ME_ATTRIBUTE_NAME;
    
    // this class from the CAS client is used to validate a service ticket on CAS server
    private TicketValidator ticketValidator;
    
    // default roles to applied to authenticated user
    private String defaultRoles;
    
    // default permissions to applied to authenticated user
    private String defaultPermissions;
    
    // names of attributes containing roles
    private String roleAttributeNames;
    
    // names of attributes containing permissions
    private String permissionAttributeNames;
    
    public CasRealm() {
        setAuthenticationTokenClass(CasToken.class);
    }

    @Override
    protected void onInit() {
        super.onInit();
        ensureTicketValidator();
    }

    protected TicketValidator ensureTicketValidator() {
        if (this.ticketValidator == null) {
            this.ticketValidator = createTicketValidator();
        }
        return this.ticketValidator;
    }
    
    protected TicketValidator createTicketValidator() {
        String urlPrefix = getCasServerUrlPrefix();
        if ("saml".equalsIgnoreCase(getValidationProtocol())) {
            return new Saml11TicketValidator(urlPrefix);
        }
        return new Cas20ServiceTicketValidator(urlPrefix);
    }
    
    /**
     * Authenticates a user and retrieves its information.
     * 
     * @param token the authentication token
     * @throws AuthenticationException if there is an error during authentication.
     */
    @Override
    @SuppressWarnings("unchecked")
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        CasToken casToken = (CasToken) token;
        if (token == null) {
            return null;
        }
        
        String ticket = (String)casToken.getCredentials();
        if (!StringUtils.hasText(ticket)) {
            return null;
        }
        
        TicketValidator ticketValidator = ensureTicketValidator();

        try {
            // contact CAS server to validate service ticket
            Assertion casAssertion = ticketValidator.validate(ticket, getCasService());
            // get principal, user id and attributes
            AttributePrincipal casPrincipal = casAssertion.getPrincipal();
            String userId = casPrincipal.getName();
            log.debug("Validate ticket : {} in CAS server : {} to retrieve user : {}", new Object[]{
                    ticket, getCasServerUrlPrefix(), userId
            });

            Map<String, Object> attributes = casPrincipal.getAttributes();
            // refresh authentication token (user id + remember me)
            casToken.setUserId(userId);
            String rememberMeAttributeName = getRememberMeAttributeName();
            String rememberMeStringValue = (String)attributes.get(rememberMeAttributeName);
            boolean isRemembered = rememberMeStringValue != null && Boolean.parseBoolean(rememberMeStringValue);
            if (isRemembered) {
                casToken.setRememberMe(true);
            }
            // create simple authentication info
            List<Object> principals = CollectionUtils.asList(userId, attributes);
            PrincipalCollection principalCollection = new SimplePrincipalCollection(principals, getName());
            return new SimpleAuthenticationInfo(principalCollection, ticket);
        } catch (TicketValidationException e) { 
            throw new CasAuthenticationException("Unable to validate ticket [" + ticket + "]", e);
        }
    }
    
    /**
     * Retrieves the AuthorizationInfo for the given principals (the CAS previously authenticated user : id + attributes).
     * 
     * @param principals the primary identifying principals of the AuthorizationInfo that should be retrieved.
     * @return the AuthorizationInfo associated with this principals.
     */
    @Override
    @SuppressWarnings("unchecked")
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        // retrieve user information
        SimplePrincipalCollection principalCollection = (SimplePrincipalCollection) principals;
        List<Object> listPrincipals = principalCollection.asList();
        Map<String, String> attributes = (Map<String, String>) listPrincipals.get(1);
        // create simple authorization info
        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        // add default roles
        addRoles(simpleAuthorizationInfo, split(defaultRoles));
        // add default permissions
        addPermissions(simpleAuthorizationInfo, split(defaultPermissions));
        // get roles from attributes
        List<String> attributeNames = split(roleAttributeNames);
        for (String attributeName : attributeNames) {
            String value = attributes.get(attributeName);
            addRoles(simpleAuthorizationInfo, split(value));
        }
        // get permissions from attributes
        attributeNames = split(permissionAttributeNames);
        for (String attributeName : attributeNames) {
            String value = attributes.get(attributeName);
            addPermissions(simpleAuthorizationInfo, split(value));
        }
        return simpleAuthorizationInfo;
    }
    
    /**
     * Split a string into a list of not empty and trimmed strings, delimiter is a comma.
     * 
     * @param s the input string
     * @return the list of not empty and trimmed strings
     */
    private List<String> split(String s) {
        List<String> list = new ArrayList<String>();
        String[] elements = StringUtils.split(s, ',');
        if (elements != null && elements.length > 0) {
            for (String element : elements) {
                if (StringUtils.hasText(element)) {
                    list.add(element.trim());
                }
            }
        }
        return list;
    }
    
    /**
     * Add roles to the simple authorization info.
     * 
     * @param simpleAuthorizationInfo
     * @param roles the list of roles to add
     */
    private void addRoles(SimpleAuthorizationInfo simpleAuthorizationInfo, List<String> roles) {
        for (String role : roles) {
            simpleAuthorizationInfo.addRole(role);
        }
    }
    
    /**
     * Add permissions to the simple authorization info.
     * 
     * @param simpleAuthorizationInfo
     * @param permissions the list of permissions to add
     */
    private void addPermissions(SimpleAuthorizationInfo simpleAuthorizationInfo, List<String> permissions) {
        for (String permission : permissions) {
            simpleAuthorizationInfo.addStringPermission(permission);
        }
    }

    public String getCasServerUrlPrefix() {
        return casServerUrlPrefix;
    }

    public void setCasServerUrlPrefix(String casServerUrlPrefix) {
        this.casServerUrlPrefix = casServerUrlPrefix;
    }

    public String getCasService() {
        return casService;
    }

    public void setCasService(String casService) {
        this.casService = casService;
    }

    public String getValidationProtocol() {
        return validationProtocol;
    }

    public void setValidationProtocol(String validationProtocol) {
        this.validationProtocol = validationProtocol;
    }

    public String getRememberMeAttributeName() {
        return rememberMeAttributeName;
    }

    public void setRememberMeAttributeName(String rememberMeAttributeName) {
        this.rememberMeAttributeName = rememberMeAttributeName;
    }

    public String getDefaultRoles() {
        return defaultRoles;
    }

    public void setDefaultRoles(String defaultRoles) {
        this.defaultRoles = defaultRoles;
    }

    public String getDefaultPermissions() {
        return defaultPermissions;
    }

    public void setDefaultPermissions(String defaultPermissions) {
        this.defaultPermissions = defaultPermissions;
    }

    public String getRoleAttributeNames() {
        return roleAttributeNames;
    }

    public void setRoleAttributeNames(String roleAttributeNames) {
        this.roleAttributeNames = roleAttributeNames;
    }

    public String getPermissionAttributeNames() {
        return permissionAttributeNames;
    }

    public void setPermissionAttributeNames(String permissionAttributeNames) {
        this.permissionAttributeNames = permissionAttributeNames;
    }
}
