package org.apache.shiro.cdi.web.producers;

import org.apache.shiro.cdi.web.ServletContainerSessions;
import org.apache.shiro.cdi.web.Web;
import org.apache.shiro.web.session.mgt.ServletContainerSessionManager;
import org.apache.shiro.web.session.mgt.WebSessionManager;

import javax.enterprise.inject.New;
import javax.enterprise.inject.Produces;

public class WebSessionManagerProvider {

    @Web
    @ServletContainerSessions
    @Produces
    protected WebSessionManager servletContainerWebSessionManager(@New ServletContainerSessionManager sessionManager) {
        return sessionManager;
    }

    @Produces
    protected WebSessionManager webSessionManager(@ServletContainerSessions WebSessionManager webSessionManager) {
        return webSessionManager;
    }

}
