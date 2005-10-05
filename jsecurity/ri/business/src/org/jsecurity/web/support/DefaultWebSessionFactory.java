package org.jsecurity.web.support;

import org.jsecurity.web.WebSessionFactory;
import org.jsecurity.session.Session;
import org.jsecurity.session.SessionFactory;

import javax.servlet.http.HttpServletRequest;

/**
 * Default JSecurity Reference Implementation of the {@link WebSessionFactory} interface.
 *
 * @author Les Hazlewood
 */
public class DefaultWebSessionFactory implements WebSessionFactory {

    SessionFactory sessionFactory;

    public DefaultWebSessionFactory(){}

    public void setSessionFactory( SessionFactory sessionFactory ) {
        this.sessionFactory = sessionFactory;
    }

    public void init() {
        if ( this.sessionFactory == null ) {
            String msg = "sessionFactory property must be set";
            throw new IllegalStateException( msg );
        }
    }

    public Session start( HttpServletRequest request ) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    public Session getSession( HttpServletRequest request ) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }
}
