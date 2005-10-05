package org.jsecurity.web.support;

import org.jsecurity.web.WebSessionFactory;
import org.jsecurity.session.Session;
import org.jsecurity.session.SessionFactory;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.servlet.http.HttpServletRequest;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Default JSecurity Reference Implementation of the {@link WebSessionFactory} interface.
 *
 * @author Les Hazlewood
 */
public class DefaultWebSessionFactory implements WebSessionFactory {

    protected transient final Log log = LogFactory.getLog( getClass() );

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

    protected InetAddress getInetAddress( HttpServletRequest request ) {
        InetAddress clientAddress = null;
        //get the Host/IP they're coming from:
        String addrString = request.getRemoteHost();
        try {
            clientAddress = InetAddress.getByName( addrString );
        } catch ( UnknownHostException e ) {
            if ( log.isWarnEnabled() ) {
                log.warn( "Unable to acquire InetAddress from HttpServletRequest, " +
                          "using null for Session creation", e );
            }
        }

        return clientAddress;
    }

    public Session start( HttpServletRequest request ) {
        InetAddress clientAddress = getInetAddress( request );
        return sessionFactory.start( clientAddress );
    }

    public Session getSession( HttpServletRequest request ) {
        //todo - implement
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }
}
