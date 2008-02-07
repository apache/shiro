package org.jsecurity.context.support;

/**
 * Interface specifying behavior for converting Subject principal(s) to and from text form.
 *
 * It is primarily used to assist in durably storing principal(s), such as for RememberMe authentication.
 */
public interface PrincipalsSerializer {

    String serialize( Object principals );

    Object deserialize( String encoded );
}
