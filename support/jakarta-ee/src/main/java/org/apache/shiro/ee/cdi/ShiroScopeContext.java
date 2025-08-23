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
package org.apache.shiro.ee.cdi;

import static org.apache.shiro.ee.filters.FormResubmitSupport.getNativeSessionManager;

import java.io.Serializable;
import java.lang.annotation.Annotation;
import jakarta.enterprise.context.spi.Context;
import jakarta.enterprise.context.spi.Contextual;
import jakarta.enterprise.context.spi.CreationalContext;
import jakarta.enterprise.inject.spi.CDI;

import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.UnavailableSecurityManagerException;
import org.apache.shiro.session.Session;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.omnifaces.cdi.BeanStorage;
import org.omnifaces.cdi.viewscope.ViewScopeManager;
import org.omnifaces.util.Beans;

/**
 * If web environment, delegate to SessionScoped,
 * otherwise use Shiro sessions to store session beans
 */
public class ShiroScopeContext implements Context, Serializable {
    private static final String BEAN_STORAGE_KEY = "org.apache.shiro.ee.bean-storage";
    private static final long serialVersionUID = 1L;
    private final Class<? extends Annotation> scopeType;
    private final Class<? extends Annotation> webScopeType;
    private final boolean isViewScoped;

    public ShiroScopeContext(Class<? extends Annotation> scopeType, Class<? extends Annotation> webScopeType) {
        this.scopeType = scopeType;
        this.webScopeType = webScopeType;
        isViewScoped = webScopeType == jakarta.faces.view.ViewScoped.class
                || webScopeType == org.omnifaces.cdi.ViewScoped.class;
    }

    @Override
    public Class<? extends Annotation> getScope() {
        return scopeType;
    }

    @Override
    public <T> T get(Contextual<T> contextual, CreationalContext<T> creationalContext) {
        if (isWebContainerSessions()) {
            Context ctx = CDI.current().getBeanManager().getContext(webScopeType);
            return ctx.get(contextual, creationalContext);
        } else {
            synchronized (contextual) {
                if (isViewScoped) {
                    return Beans.getReference(ViewScopeManager.class).createBean(contextual, creationalContext);
                } else {
                    return getBeanStorage(SecurityUtils.getSubject().getSession())
                            .createBean(contextual, creationalContext);
                }
            }
        }
    }

    @Override
    public <T> T get(Contextual<T> contextual) {
        if (isWebContainerSessions()) {
            Context ctx = CDI.current().getBeanManager().getContext(webScopeType);
            return ctx.get(contextual);
        } else {
            if (isViewScoped) {
                return Beans.getReference(ViewScopeManager.class).getBean(contextual);
            } else {
                return getBeanStorage(SecurityUtils.getSubject().getSession()).getBean(contextual);
            }
        }
    }

    @Override
    public boolean isActive() {
        return true;
    }

    @SuppressWarnings("MagicNumber")
    void onCreate(Session session) {
        session.setAttribute(BEAN_STORAGE_KEY, new BeanStorage(20));
    }

    void onDestroy(Session session) {
        getBeanStorage(session).destroyBeans();
    }

    public static boolean isWebContainerSessions(SecurityManager sm) {
        if (sm instanceof WebSecurityManager) {
            WebSecurityManager wsm = (WebSecurityManager) sm;
            return wsm.isHttpSessionMode();
        }
        return false;
    }

    public static void addScopeSessionListeners(WebSecurityManager wsm) {
        if (!isWebContainerSessions(wsm)) {
            var dsm = getNativeSessionManager(wsm);
            Beans.getReference(ShiroSessionScopeExtension.class)
                    .addSessionListeners(dsm.getSessionListeners(), wsm);
        }
    }

    static boolean isWebContainerSessions() {
        try {
            return isWebContainerSessions(SecurityUtils.getSecurityManager());
        } catch (UnavailableSecurityManagerException unavailable) {
            return true;
        }
    }

    private BeanStorage getBeanStorage(Session session) {
        return (BeanStorage) session.getAttribute(BEAN_STORAGE_KEY);
    }
}
