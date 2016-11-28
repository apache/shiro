package org.apache.shiro.cdi.web;

import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.web.env.WebEnvironment;
import org.apache.shiro.web.filter.mgt.FilterChainResolver;
import org.apache.shiro.web.mgt.WebSecurityManager;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.ServletContext;

@ApplicationScoped
public class CdiWebEnvironment implements WebEnvironment {

    @Inject
    private FilterChainResolver filterChainResolver;

    @Inject
    private WebSecurityManager webSecurityManager;

    @Inject
    private ServletContext servletContext;

    @Override
    public FilterChainResolver getFilterChainResolver() {
        return filterChainResolver;
    }

    @Override
    public SecurityManager getSecurityManager() {
        return webSecurityManager;
    }

    @Override
    public WebSecurityManager getWebSecurityManager() {
        return webSecurityManager;
    }

    @Override
    public ServletContext getServletContext() {
        return servletContext;
    }
}
