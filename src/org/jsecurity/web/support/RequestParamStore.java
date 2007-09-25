package org.jsecurity.web.support;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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

    protected T onRetrieveValue( HttpServletRequest request, HttpServletResponse response ) {
        return getFromRequestParam( request );
    }

    protected void onStoreValue( T value, HttpServletRequest request, HttpServletResponse response ) {
        throw new UnsupportedOperationException( "RequestParamStores are read-only." );
    }
}
