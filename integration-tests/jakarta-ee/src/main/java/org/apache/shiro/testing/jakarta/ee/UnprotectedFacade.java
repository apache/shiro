/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.shiro.testing.jakarta.ee;

import static org.apache.shiro.ee.cdi.ShiroScopeContext.isWebContainerSessions;

import org.apache.shiro.ee.filters.Forms;

import java.util.Map;
import javax.ejb.EJBException;
import javax.enterprise.inject.Model;
import javax.inject.Inject;

import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.UnauthenticatedException;

import static org.omnifaces.util.Exceptions.unwrap;

import org.omnifaces.util.Messages;

/**
 * Facade for all types of Shiro-protected beans
 */
@Model
@Slf4j
public class UnprotectedFacade {
    @Inject
    ProtectedFacesViewScopedBean viewScoped;

    @Inject
    ProtectedOmniViewScopedBean omniViewScoped;

    @Inject
    ProtectedSessionScopedBean sessionScoped;

    @Inject
    ProtectedStatelessBean stateless;

    @Inject
    ProtectedOneMethod protectedOneMethod;

    public void callFacesViewScoped() {
        try {
            Messages.addGlobalInfo(viewScoped.hello());
        } catch (UnauthenticatedException e) {
            Messages.addGlobalInfo("view scope unauth: {0}", e.getMessage());
        }
    }

    public void callOmniViewScoped() {
        try {
            Messages.addGlobalInfo(omniViewScoped.hello());
        } catch (UnauthenticatedException e) {
            Messages.addGlobalInfo("omni view scope unauth: {0}", e.getMessage());
        }
    }

    public void callSessionScoped() {
        try {
            Messages.addGlobalInfo(sessionScoped.hello());
        } catch (UnauthenticatedException e) {
            Messages.addGlobalInfo("session scoped unauth: {0}", e.getMessage());
        }
    }

    public void callStatelessBean() {
        try {
            if (!Forms.isLoggedIn()) {
                log.info("*=*=*=*= The next WARNING is legit, it's expected");
            }
            Messages.addGlobalInfo(stateless.hello());
        } catch (EJBException e) {
            var real = unwrap(e, EJBException.class);
            if (real instanceof UnauthenticatedException) {
                Messages.addGlobalInfo("stateless bean unauth: {0}", e.getMessage());
            } else {
                Messages.addGlobalError("Stateless - Unexpected Exception: {0}", e.getMessage());
            }
        }
    }

    public void callUnprotectedMethod() {
        try {
            Messages.addGlobalInfo("unprotected method: {0}", protectedOneMethod.unprotectedMethod());
        } catch (UnauthenticatedException e) {
            Messages.addGlobalInfo("unprotected unauth: {0}", e.getMessage());
        }
    }

    public void callProtectedMethod() {
        try {
            Messages.addGlobalInfo("protected method: {0}", protectedOneMethod.protectedMethod());
        } catch (UnauthenticatedException e) {
            Messages.addGlobalInfo("protected unauth: {0}", e.getMessage());
        }
    }

    public Map<?, ?> getStatistics() {
        return StatisticsResource.getStatistics();
    }

    public boolean isUsingWebSessions() {
        return isWebContainerSessions(SecurityUtils.getSecurityManager());
    }
}
