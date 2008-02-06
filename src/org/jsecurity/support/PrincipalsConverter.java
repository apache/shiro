package org.jsecurity.support;

/**
 * Interface specifying behavior for converting a Subject principal/principals to and from text form.
 *
 * It is primarily used in storing principal(s) durably, such as for RememberMe authentication.
 */
public interface PrincipalsConverter {

    String toString( Object principals );

    Object fromString( String src );
}
