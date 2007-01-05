package org.jsecurity.web.support;

import java.beans.PropertyEditorSupport;
import java.util.UUID;

/**
 * Insert JavaDoc here.
 */
public class UUIDEditor extends PropertyEditorSupport {

    public String getAsText() {
        if( getValue() == null ) {
            return null;
        } else {
            return getValue().toString();
        }
    }

    public void setAsText(String text) throws IllegalArgumentException {
        if( text != null && text.length() > 0 ) {
            setValue( UUID.fromString( text ) );
        } else {
            setValue( null );
        }

    }
}
