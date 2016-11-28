package org.apache.shiro.cdi.producers;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;

import javax.enterprise.context.RequestScoped;
import javax.enterprise.inject.Produces;

public class SubjectProducer {

    @Produces
    @RequestScoped
    protected Subject subject(SecurityManager securityManager) {
        if (ThreadContext.getSecurityManager() == null) {
            ThreadContext.bind(securityManager);
        }
        return SecurityUtils.getSubject();
    }
}
