package org.jsecurity.web.attr;

import junit.framework.TestCase;
import static org.easymock.EasyMock.*;
import org.junit.Before;
import org.junit.Test;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Created by IntelliJ IDEA.
 * User: lhazlewood
 * Date: Mar 27, 2008
 * Time: 10:35:45 PM
 * To change this template use File | Settings | File Templates.
 */
public class CookieAttributeTest extends TestCase {

    private CookieAttribute<String> cookieAttribute;
    private HttpServletRequest mockRequest;
    private HttpServletResponse mockResponse;

    @Before
    public void setUp() throws Exception {
        this.mockRequest = createMock(HttpServletRequest.class);
        this.mockResponse = createMock(HttpServletResponse.class);
        this.cookieAttribute = new CookieAttribute<String>("test");
    }

    @Test
    //Verifies fix for JSEC-94
    public void testRemoveValue() throws Exception {

        Cookie cookie = new Cookie("test","blah");
        cookie.setMaxAge( 2351234 ); //doesn't matter what the time is
        Cookie[] cookies = new Cookie[] { cookie };

        expect( mockRequest.getCookies() ).andReturn(cookies);
        //no path set on the cookie, so we expect to retrieve it from the context path
        expect( mockRequest.getContextPath() ).andReturn( "/somepath" );
        mockResponse.addCookie(cookie);
        replay(mockRequest);
        replay(mockResponse);

        cookieAttribute.removeValue(mockRequest,mockResponse);

        verify(mockRequest);
        verify(mockResponse);

        assertTrue( cookie.getMaxAge() == 0 );
        assertTrue( cookie.getPath().equals("/somepath" ) );
    }
}
