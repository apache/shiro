/*
 * Copyright 2013 Harald Wellmann
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.ops4j.pax.shiro.cdi.impl;

import static org.apache.shiro.SecurityUtils.getSecurityManager;
import static org.apache.shiro.SecurityUtils.getSubject;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Produces;

import org.apache.shiro.ShiroException;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;

@ApplicationScoped
public class ShiroProducer {

    @Produces
    public Subject subject() {
        return proxy(Subject.class, new SubjectInvocationHandler());
    }

    @Produces
    public SecurityManager securityManager() {
        return proxy(SecurityManager.class, new SecurityManagerInvocationHandler());
    }

    @Produces
    public Session session() {
        return proxy(Session.class, new SessionInvocationHandler());
    }
    
    private static ShiroException unwrap(InvocationTargetException exc) {
        if (exc.getCause() instanceof ShiroException) {
            return (ShiroException) exc.getCause();
        }
        else  {
            return new ShiroException(exc.getCause());
        }
    }

    @SuppressWarnings("unchecked")
    private <T> T proxy(final Class<T> clazz, final InvocationHandler ih) {
        ClassLoader cl = getClass().getClassLoader();
        return (T) Proxy.newProxyInstance(cl, new Class<?>[] { clazz }, ih);
    }

    private static class SubjectInvocationHandler extends Handler {

        public Object handlerInvoke(final Object proxy, final Method method, final Object[] args) {
            try {
                return method.invoke(getSubject(), args);
            }
            catch (IllegalAccessException exc) {
                throw new ShiroException(exc);
            }
            catch (IllegalArgumentException exc) {
                throw new ShiroException(exc);
            }
            catch (InvocationTargetException exc) {
                throw unwrap(exc);
            }
        }
    }

    private class SecurityManagerInvocationHandler extends Handler {

        private SecurityManager delegate = getSecurityManager();
        
        public Object handlerInvoke(Object proxy, Method method, Object[] args) {
            try {
                SecurityManager sm = getSecurityManager();
                // avoid infinite recursion
                if (sm == proxy) {
                    sm = delegate;
                }
                return method.invoke(sm, args);
            }
            catch (IllegalAccessException exc) {
                throw new ShiroException(exc);
            }
            catch (IllegalArgumentException exc) {
                throw new ShiroException(exc);
            }
            catch (InvocationTargetException exc) {
                throw unwrap(exc);
            }
        }
    }

    private class SessionInvocationHandler extends Handler {

        public Object handlerInvoke(Object proxy, Method method, Object[] args) {
            try {
                return method.invoke(getSubject().getSession(), args);
            }
            catch (IllegalAccessException exc) {
                throw new ShiroException(exc);
            }
            catch (IllegalArgumentException exc) {
                throw new ShiroException(exc);
            }
            catch (InvocationTargetException exc) {
                throw unwrap(exc);
            }
        }
    }

    private abstract static class Handler implements InvocationHandler {

        public abstract Object handlerInvoke(Object proxy, Method method, Object[] args);

        public Object invoke(Object proxy, Method method, Object[] args) {
            return handlerInvoke(proxy, method, args);
        }
    }
}
