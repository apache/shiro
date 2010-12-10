package org.apache.shiro.samples.spring.realm;

import org.apache.shiro.authc.*;
import org.apache.shiro.realm.jdbc.JdbcRealm;
import org.apache.shiro.util.JdbcUtils;
import org.apache.shiro.util.SimpleByteSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Realm that exists to support salted credentials.  The JdbcRealm implementation needs to be updated in a future
 * Shiro release to handle this.
 */
public class SaltAwareJdbcRealm extends JdbcRealm {

    private static final Logger log = LoggerFactory.getLogger(SaltAwareJdbcRealm.class);

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        UsernamePasswordToken upToken = (UsernamePasswordToken) token;
        String username = upToken.getUsername();

        // Null username is invalid
        if (username == null) {
            throw new AccountException("Null usernames are not allowed by this realm.");
        }

        Connection conn = null;
        AuthenticationInfo info = null;
        try {
            conn = dataSource.getConnection();

            String password = getPasswordForUser(conn, username);

            if (password == null) {
                throw new UnknownAccountException("No account found for user [" + username + "]");
            }

            SimpleAuthenticationInfo saInfo = new SimpleAuthenticationInfo(username, password, getName());
            /**
             * This (very bad) example uses the username as the salt in this sample app.  DON'T DO THIS IN A REAL APP!
             *
             * Salts should not be based on anything that a user could enter (attackers can exploit this).  Instead
             * they should ideally be cryptographically-strong randomly generated numbers.
             */
            saInfo.setCredentialsSalt(new SimpleByteSource(username));

            info = saInfo;

        } catch (SQLException e) {
            final String message = "There was a SQL error while authenticating user [" + username + "]";
            if (log.isErrorEnabled()) {
                log.error(message, e);
            }

            // Rethrow any SQL errors as an authentication exception
            throw new AuthenticationException(message, e);
        } finally {
            JdbcUtils.closeConnection(conn);
        }

        return info;
    }

    private String getPasswordForUser(Connection conn, String username) throws SQLException {

        PreparedStatement ps = null;
        ResultSet rs = null;
        String password = null;
        try {
            ps = conn.prepareStatement(authenticationQuery);
            ps.setString(1, username);

            // Execute query
            rs = ps.executeQuery();

            // Loop over results - although we are only expecting one result, since usernames should be unique
            boolean foundResult = false;
            while (rs.next()) {

                // Check to ensure only one row is processed
                if (foundResult) {
                    throw new AuthenticationException("More than one user row found for user [" + username + "]. Usernames must be unique.");
                }

                password = rs.getString(1);

                foundResult = true;
            }
        } finally {
            JdbcUtils.closeResultSet(rs);
            JdbcUtils.closeStatement(ps);
        }

        return password;
    }

}
