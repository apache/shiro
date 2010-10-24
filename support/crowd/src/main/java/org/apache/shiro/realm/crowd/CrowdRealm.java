/**
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.shiro.realm.crowd;

import java.rmi.RemoteException;
import java.util.EnumSet;

import com.atlassian.crowd.integration.exception.ApplicationAccessDeniedException;
import com.atlassian.crowd.integration.exception.InactiveAccountException;
import com.atlassian.crowd.integration.exception.InvalidAuthenticationException;
import com.atlassian.crowd.integration.exception.InvalidAuthorizationTokenException;
import com.atlassian.crowd.integration.exception.ObjectNotFoundException;
import com.atlassian.crowd.integration.service.soap.client.SecurityServerClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.DisabledAccountException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.pam.UnsupportedTokenException;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;


/**
 * A realm that authenticates and obtains its roles from a Atlassian Crowd
 * server.
 * <p/>
 * The Crowd server as the concept of role and group memberships.  Both of
 * which can be can be mapped to Shiro roles.  This realm implementation
 * allows the deployer to select either or both memberships to map to Shiro
 * roles.
 *
 * @version $Rev$ $Date$
 */
public class CrowdRealm extends AuthorizingRealm {

    private static final Logger LOG = LoggerFactory.getLogger(CrowdRealm.class);
    private SecurityServerClient crowdClient;
    private EnumSet<RoleSource> roleSources = EnumSet.of(RoleSource.ROLES_FROM_CROWD_ROLES);

    /**
     * A simple constructor for a Shiro Crowd realm.
     * <p/>
     * It is expected that an initialized Crowd client will be subsequently
     * set using {@link #setCrowdClient(SecurityServerClient)}.
     */
    public CrowdRealm() {
    }

    /**
     * Initialize the Shiro Crowd realm with an instance of
     * {@link SecurityServerClient}.  The method {@link SecurityServerClient#authenticate}
     * is assumed to be called by the creator of this realm.
     *
     * @param crowdClient an instance of {@link SecurityServerClient} to be used when communicating with the Crowd server
     */
    public CrowdRealm(SecurityServerClient crowdClient) {
        if (crowdClient == null) throw new IllegalArgumentException("Crowd client cannot be null");

        this.crowdClient = crowdClient;
    }

    /**
     * Set the client to use when communicating with the Crowd server.
     * <p/>
     * It is assumed that the Crowd client has already authenticated with the
     * Crowd server.
     *
     * @param crowdClient the client to use when communicating with the Crowd server
     */
    public void setCrowdClient(SecurityServerClient crowdClient) {
        this.crowdClient = crowdClient;
    }

    /**
     * Obtain the kinds of Crowd memberships that will serve as sources for
     * Shiro roles.
     *
     * @return an enum set of role source directives.
     */
    public EnumSet<RoleSource> getRoleSources() {
        return roleSources;
    }

    /**
     * Set the kinds of Crowd memberships that will serve as sources for
     * Shiro roles.
     *
     * @param roleSources an enum set of role source directives.
     */
    public void setRoleSources(EnumSet<RoleSource> roleSources) {
        this.roleSources = roleSources;
    }

    /**
     * {@inheritDoc}
     */
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {

        if (LOG.isTraceEnabled()) LOG.trace("Collecting authorization info from realm " + getName());

        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();

        for (Object principal : principalCollection.fromRealm(getName())) {
            if (LOG.isTraceEnabled()) LOG.trace("Collecting roles from " + principal);

            try {
                if (roleSources.contains(RoleSource.ROLES_FROM_CROWD_ROLES)) {
                    if (LOG.isTraceEnabled()) LOG.trace("Collecting Shiro roles from Crowd role memberships");

                    for (String role : crowdClient.findRoleMemberships(principal.toString())) {
                        if (LOG.isTraceEnabled()) LOG.trace("Adding role " + role);

                        authorizationInfo.addRole(role);
                    }
                }

                if (roleSources.contains(RoleSource.ROLES_FROM_CROWD_GROUPS)) {
                    if (LOG.isTraceEnabled()) LOG.trace("Collecting Shiro roles from Crowd group memberships");

                    for (String group : crowdClient.findGroupMemberships(principal.toString())) {
                        if (LOG.isTraceEnabled()) LOG.trace("Adding role " + group);

                        authorizationInfo.addRole(group);
                    }
                }
            } catch (InvalidAuthorizationTokenException iae) {
                throw new AuthorizationException("Unable to obtain Crowd group memberships for principal " + principal + ".", iae);
            } catch (RemoteException re) {
                throw new AuthorizationException("Unable to obtain Crowd group memberships for principal " + principal + ".", re);
            } catch (ObjectNotFoundException onfe) {
                throw new AuthorizationException("Unable to obtain Crowd group memberships for principal " + principal + ".", onfe);
            }
        }

        return authorizationInfo;
    }

    /**
     * {@inheritDoc}
     */
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {

        if (LOG.isTraceEnabled()) LOG.trace("Collecting authentication info from realm " + getName());

        if (!(authenticationToken instanceof UsernamePasswordToken)) {
            throw new UnsupportedTokenException("Unsupported token of type " + authenticationToken.getClass().getName() + ".  "
                                                + UsernamePasswordToken.class.getName() + " is required.");
        }

        UsernamePasswordToken token = (UsernamePasswordToken) authenticationToken;
        try {
            crowdClient.authenticatePrincipalSimple(token.getUsername(), new String(token.getPassword()));

            return new SimpleAuthenticationInfo(token.getPrincipal(), token.getCredentials(), getName());
        }
        catch (InvalidAuthorizationTokenException iate) {
            throw new AuthenticationException("Unable to obtain authenticate principal " + token.getUsername() + " in Crowd.", iate);
        }
        catch (ApplicationAccessDeniedException aade) {
            throw new AuthenticationException("Unable to obtain authenticate principal " + token.getUsername() + " in Crowd.", aade);
        }
        catch (InvalidAuthenticationException iae) {
            throw new IncorrectCredentialsException("Unable to authenticate principal " + token.getUsername() + " in Crowd.", iae);
        }
        catch (RemoteException re) {
            throw new AuthenticationException("Unable to obtain authenticate principal " + token.getUsername() + " in Crowd.", re);
        }
        catch (InactiveAccountException iae) {
            throw new DisabledAccountException("Disabled principal " + token.getUsername() + " in Crowd.", iae);
        }
    }
}
