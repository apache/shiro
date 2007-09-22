package org.jsecurity.web.servlet;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletRequest;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Map;

/**
 * TODO class JavaDoc
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public class JSecurityServletRequest implements ServletRequest {

    protected ServletRequest wrapped = null;

    public JSecurityServletRequest( ServletRequest wrapped ) {
        this.wrapped = wrapped;
    }

    public Object getAttribute( String s ) {
        return wrapped.getAttribute( s );
    }

    public Enumeration getAttributeNames() {
        return wrapped.getAttributeNames();
    }

    public String getCharacterEncoding() {
        return wrapped.getCharacterEncoding();
    }

    public void setCharacterEncoding( String s ) throws UnsupportedEncodingException {
        wrapped.setCharacterEncoding( s );
    }

    public int getContentLength() {
        return wrapped.getContentLength();
    }

    public String getContentType() {
        return wrapped.getContentType();
    }

    public ServletInputStream getInputStream() throws IOException {
        return wrapped.getInputStream();
    }

    public String getParameter( String s ) {
        return wrapped.getParameter( s );
    }

    public Enumeration getParameterNames() {
        return wrapped.getParameterNames();
    }

    public String[] getParameterValues( String s ) {
        return wrapped.getParameterValues( s );
    }

    public Map getParameterMap() {
        return wrapped.getParameterMap();
    }

    public String getProtocol() {
        return wrapped.getProtocol();
    }

    public String getScheme() {
        return wrapped.getScheme();
    }

    public String getServerName() {
        return wrapped.getServerName();
    }

    public int getServerPort() {
        return wrapped.getServerPort();
    }

    public BufferedReader getReader() throws IOException {
        return wrapped.getReader();
    }

    public String getRemoteAddr() {
        return wrapped.getRemoteAddr();
    }

    public String getRemoteHost() {
        return wrapped.getRemoteHost();
    }

    public void setAttribute( String s, Object o ) {
        wrapped.setAttribute( s, o );
    }

    public void removeAttribute( String s ) {
        wrapped.removeAttribute( s );
    }

    public Locale getLocale() {
        return wrapped.getLocale();
    }

    public Enumeration getLocales() {
        return wrapped.getLocales();
    }

    public boolean isSecure() {
        return wrapped.isSecure();
    }

    public RequestDispatcher getRequestDispatcher( String s ) {
        return wrapped.getRequestDispatcher( s );
    }

    public String getRealPath( String s ) {
        return wrapped.getRealPath( s );
    }

    public int getRemotePort() {
        return wrapped.getRemotePort();
    }

    public String getLocalName() {
        return wrapped.getLocalName();
    }

    public String getLocalAddr() {
        return wrapped.getLocalAddr();
    }

    public int getLocalPort() {
        return wrapped.getLocalPort();
    }
}
