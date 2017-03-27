package org.apache.shiro.web.servlet;

import org.apache.shiro.web.env.WebEnvironment;

/**
 * A variant of the {@link ShiroFilter} that instantiates the required
 * {@link WebEnvironment} if not already available. This may be, e.g. the case
 * in an OSGI environment, where the possibility to register the resp.
 * ServletContextListener might not be available.
 * 
 * @since 1.4
 */
public class WebEnvironmentShiroFilter extends ShiroFilter {

	public WebEnvironmentShiroFilter() {
		super(true);
	}
}
