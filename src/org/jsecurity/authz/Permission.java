package org.jsecurity.authz;

/**
 * Created by IntelliJ IDEA.
 * User: lhazlewood
 * Date: Mar 2, 2007
 * Time: 3:14:10 PM
 * To change this template use File | Settings | File Templates.
 */
public interface Permission {

    String getTargetName();

    boolean implies( Permission p );

    String toString();

    boolean equals( Object o );

    int hashCode();
}
