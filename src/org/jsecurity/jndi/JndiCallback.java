package org.jsecurity.jndi;

import javax.naming.Context;
import javax.naming.NamingException;

/**
 * Callback interface to be implemented by classes that need to perform an
 * operation (such as a lookup) in a JNDI context. This callback approach
 * is valuable in simplifying error handling, which is performed by the
 * JndiTemplate class. This is a similar to JdbcTemplate's approach.
 *
 * <p>Note that there is hardly any need to implement this callback
 * interface, as JndiTemplate provides all usual JNDI operations via
 * convenience methods.
 *
 * <p>Note that this interface is an exact copy of the Spring Framework's identically named interface from
 * their 2.5.4 distribution - we didn't want to re-invent the wheel, but not require a full dependency on the
 * Spring framework, nor does Spring make available only its JNDI classes in a small jar, or we would have used that.
 * Since JSecurity is also Apache 2.0 licensed, all regular licenses and conditions and authors have remained in tact.
 *
 * @author Rod Johnson
 * @see JndiTemplate
 * @see org.springframework.jdbc.core.JdbcTemplate
 */
public interface JndiCallback {

    /**
     * Do something with the given JNDI context.
     * Implementations don't need to worry about error handling
     * or cleanup, as the JndiTemplate class will handle this.
     *
     * @param ctx the current JNDI context
     * @return a result object, or <code>null</code>
     * @throws NamingException if thrown by JNDI methods
     */
    Object doInContext(Context ctx) throws NamingException;

}
