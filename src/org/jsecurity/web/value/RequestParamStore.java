package org.jsecurity.web.value;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * TODO class JavaDoc
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public class RequestParamStore<T> extends AbstractWebStore<T> {

    public RequestParamStore() {
        setCheckRequestParams( false );
    }

    public RequestParamStore( String name ) {
        super( name );
        setCheckRequestParams( false );
    }

    protected T onRetrieveValue( ServletRequest request, ServletResponse response ) {
        return getFromRequestParam( request );
    }

    protected void onStoreValue( T value, ServletRequest request, ServletResponse response ) {
        throw new UnsupportedOperationException( "RequestParamStores are read-only." );
    }

    public void removeValue(ServletRequest request, ServletResponse response) {
        //no op - can't alter request attributes
        if ( log.isWarnEnabled() ) {
            String msg = "Asked to remove WebStore value.  A " + getClass().getName() + " implementation " +
                "cannot remove values from the request params.";
        }
    }
}
