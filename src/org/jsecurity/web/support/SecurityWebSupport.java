package org.jsecurity.web.support;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.util.Initializable;
import org.jsecurity.util.ThreadContext;

import javax.servlet.http.HttpServletRequest;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * TODO class JavaDoc
 *
 * @author Les Hazlewood
 */
public abstract class SecurityWebSupport implements Initializable {

    private static transient final Log staticLog = LogFactory.getLog( SecurityWebSupport.class );
    protected transient final Log log = LogFactory.getLog( getClass() );

    public static InetAddress getInetAddress( HttpServletRequest request ) {
        InetAddress clientAddress = null;
        //get the Host/IP the client is coming from:
        String addrString = request.getRemoteHost();
        try {
            clientAddress = InetAddress.getByName( addrString );
        } catch ( UnknownHostException e ) {
            if ( staticLog.isInfoEnabled() ) {
                staticLog.info( "Unable to acquire InetAddress from HttpServletRequest", e );
            }
        }

        return clientAddress;
    }

    protected void bindInetAddressToThread( HttpServletRequest request ) {
        InetAddress ip = getInetAddress( request );
        if ( ip != null ) {
            ThreadContext.bind( ip );
        }
    }

    protected void unbindInetAddressFromThread() {
        ThreadContext.unbindInetAddress();
    }

}
