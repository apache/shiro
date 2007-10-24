package org.jsecurity;

import java.security.Principal;
import java.io.Serializable;

public class UsernamePrincipal implements Principal, Serializable {


    private String username;

    public UsernamePrincipal(String username) {
        this.username = username;
    }

    public String getUsername() {
        return username;
    }

    public String getName() {
        return String.valueOf(username);
    }
}
