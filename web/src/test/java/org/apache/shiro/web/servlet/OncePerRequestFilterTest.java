package org.apache.shiro.web.servlet;

import org.junit.Before;
import org.junit.Test;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

/**
 * Unit tests for the {@link OncePerRequestFilter} implementation.
 *
 * @since 1.2
 */
public class OncePerRequestFilterTest {

    private static final boolean[] FILTERED = new boolean[1];
    private static final String NAME = "oncePerRequestFilter";
    private static final String ATTR_NAME = NAME + OncePerRequestFilter.ALREADY_FILTERED_SUFFIX;

    private OncePerRequestFilter filter;
    private FilterChain chain;
    private ServletRequest request;
    private ServletResponse response;

    @Before
    public void setUp() {
        FILTERED[0] = false;
        filter = createTestInstance();
        chain = createNiceMock(FilterChain.class);
        request = createNiceMock(ServletRequest.class);
        response = createNiceMock(ServletResponse.class);
    }

    private OncePerRequestFilter createTestInstance() {
        OncePerRequestFilter filter = new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(ServletRequest request, ServletResponse response, FilterChain chain)
                    throws ServletException, IOException {
                FILTERED[0] = true;
            }
        };
        filter.setName(NAME);

        return filter;
    }

    /**
     * Test asserting <a href="https://issues.apache.org/jira/browse/SHIRO-221">SHIRO-221<a/>.
     */
    @SuppressWarnings({"JavaDoc"})
    @Test
    public void testEnabled() throws IOException, ServletException {
        expect(request.getAttribute(ATTR_NAME)).andReturn(null).anyTimes();
        replay(request);

        filter.doFilter(request, response, chain);

        verify(request);
        assertTrue("Filter should have executed", FILTERED[0]);
    }

    /**
     * Test asserting <a href="https://issues.apache.org/jira/browse/SHIRO-221">SHIRO-221<a/>.
     */
    @SuppressWarnings({"JavaDoc"})
    @Test
    public void testDisabled() throws IOException, ServletException {
        filter.setEnabled(false); //test disabled

        expect(request.getAttribute(ATTR_NAME)).andReturn(null).anyTimes();
        replay(request);

        filter.doFilter(request, response, chain);

        verify(request);
        assertFalse("Filter should NOT have executed", FILTERED[0]);
    }

}
