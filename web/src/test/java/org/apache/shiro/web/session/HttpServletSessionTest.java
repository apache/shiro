package org.apache.shiro.web.session;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.assertEquals;

import javax.servlet.http.HttpSession;

import org.easymock.Capture;
import org.junit.Before;
import org.junit.Test;

public class HttpServletSessionTest {

    private HttpSession mockSession;

    @Before
    public void setUp() throws Exception {
        this.mockSession = createMock(HttpSession.class);
    }

    /*
     * Shiro-421
     * Tests that the conversion of a httpSession timeout interval from seconds to milliseconds doesn't overflow.
     * @since 1.3
     */
    @Test
    public void testLongTimeout() throws Exception {
        final int expectedTimeoutInSeconds = 30 * 24 * 60 * 60;  // 30 days.
        final long expectedLongValue = expectedTimeoutInSeconds * 1000L;

        Capture<Integer> capturedInt = new Capture<Integer>();
        // use a capture to make sure the setter is doing the right thing.
        mockSession.setMaxInactiveInterval(captureInt(capturedInt));
        expect(mockSession.getMaxInactiveInterval()).andReturn(expectedTimeoutInSeconds);
        replay(mockSession);

        HttpServletSession servletSession = new HttpServletSession(mockSession, null);
        servletSession.setTimeout(expectedLongValue);

        long timeoutInMilliseconds = servletSession.getTimeout();

        assertEquals(expectedLongValue, timeoutInMilliseconds);
        assertEquals(expectedTimeoutInSeconds, capturedInt.getValue().intValue());
    }
}
