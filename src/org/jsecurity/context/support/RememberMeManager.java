package org.jsecurity.context.support;

import org.jsecurity.authc.event.AuthenticationEventListener;

/**
 * @author Les Hazlewood
 * @since 1.0
 */
public interface RememberMeManager extends AuthenticationEventListener {

    Object getRememberedIdentity();
    
}
