package org.jsecurity.authc.event.mgt;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authc.Account;
import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.event.AuthenticationEvent;
import org.jsecurity.authc.event.AuthenticationEventListener;

import java.util.Collection;

/**
 * @author Les Hazlewood
 * @since 0.9
 */
public class DefaultAuthenticationEventManager implements AuthenticationEventManager {

    protected transient final Log log = LogFactory.getLog( getClass() );

    protected AuthenticationEventFactory authenticationEventFactory = new DefaultAuthenticationEventFactory();
    protected AuthenticationEventSender authenticationEventSender = new DefaultAuthenticationEventSender();

    public DefaultAuthenticationEventManager(){}

    public AuthenticationEventFactory getAuthenticationEventFactory() {
        return authenticationEventFactory;
    }

    public void setAuthenticationEventFactory(AuthenticationEventFactory authenticationEventFactory) {
        this.authenticationEventFactory = authenticationEventFactory;
    }

    public AuthenticationEventSender getAuthenticationEventSender() {
        return authenticationEventSender;
    }

    public void setAuthenticationEventSender(AuthenticationEventSender authenticationEventSender) {
        this.authenticationEventSender = authenticationEventSender;
    }

    public AuthenticationEvent createFailureEvent(AuthenticationToken token, AuthenticationException ex) {
        return this.authenticationEventFactory.createFailureEvent(token,ex);
    }

    public AuthenticationEvent createSuccessEvent(AuthenticationToken token, Account account) {
        return this.authenticationEventFactory.createSuccessEvent(token,account);
    }

    public AuthenticationEvent createLogoutEvent(Object subjectPrincipal) {
        return this.authenticationEventFactory.createLogoutEvent(subjectPrincipal);
    }

    public void send(AuthenticationEvent ae) {
        this.authenticationEventSender.send(ae);
    }

    public void setAuthenticationEventListeners(Collection<AuthenticationEventListener> listeners) {
        this.authenticationEventSender.setAuthenticationEventListeners(listeners);
    }

    public void add(AuthenticationEventListener listener) {
        this.authenticationEventSender.add(listener);
    }

    public boolean remove(AuthenticationEventListener listener) {
        return authenticationEventSender.remove(listener);
    }

    public boolean isSendingEvents() {
        return authenticationEventSender.isSendingEvents();
    }
}
