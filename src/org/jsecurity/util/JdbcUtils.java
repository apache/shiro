/*
 * Copyright (C) 2005-2007 Jeremy Haile
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the
 *
 * Free Software Foundation, Inc.
 * 59 Temple Place, Suite 330
 * Boston, MA 02111-1307
 * USA
 *
 * Or, you may view it online at
 * http://www.opensource.org/licenses/lgpl-license.php
 */
package org.jsecurity.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * <p>
 * A set of static helper methods for managing JDBC API objects.
 * </p>
 *
 * <p>
 * Some parts of this class were copied from the Spring Framework and then modified.
 * They were copied here to prevent Spring dependencies in the JSecurity core API.
 * </p>
 * 
 * @author Jeremy Haile
 * @since 0.2
 */
public class JdbcUtils {

    /**
     * Commons-logger.
     */
    protected static transient final Log log = LogFactory.getLog(JdbcUtils.class);

    /**
     * Private constructor to prevent instantiation.
     */
    private JdbcUtils() {
    }

    /**
     * Close the given JDBC Connection and ignore any thrown exception.
     * This is useful for typical finally blocks in manual JDBC code.
     *
     * @param connection the JDBC Connection to close (may be <tt>null</tt>)
     */
    public static void closeConnection(Connection connection) {
        if (connection != null) {
            try {
                connection.close();
            } catch (SQLException ex) {
                if( log.isDebugEnabled() ) {
                    log.debug("Could not close JDBC Connection", ex);
                }
            } catch (Throwable ex) {
                if( log.isDebugEnabled() ) {
                    log.debug("Unexpected exception on closing JDBC Connection", ex);
                }
            }
        }
    }

    /**
     * Close the given JDBC Statement and ignore any thrown exception.
     * This is useful for typical finally blocks in manual JDBC code.
     *
     * @param statement the JDBC Statement to close (may be <tt>null</tt>)
     */
    public static void closeStatement(Statement statement) {
        if (statement != null) {
            try {
                statement.close();
            } catch (SQLException ex) {
                if( log.isDebugEnabled() ) {
                    log.debug("Could not close JDBC Statement", ex);
                }
            } catch (Throwable ex) {
                if( log.isDebugEnabled() ) {
                    log.debug("Unexpected exception on closing JDBC Statement", ex);
                }
            }
        }
    }

    /**
     * Close the given JDBC ResultSet and ignore any thrown exception.
     * This is useful for typical finally blocks in manual JDBC code.
     *
     * @param rs the JDBC ResultSet to close (may be <tt>null</tt>)
     */
    public static void closeResultSet(ResultSet rs) {
        if (rs != null) {
            try {
                rs.close();
            } catch (SQLException ex) {
                if( log.isDebugEnabled() ) {
                    log.debug("Could not close JDBC ResultSet", ex);
                }
            } catch (Throwable ex) {
                if( log.isDebugEnabled() ) {
                    log.debug("Unexpected exception on closing JDBC ResultSet", ex);
                }
            }
        }
    }

}
