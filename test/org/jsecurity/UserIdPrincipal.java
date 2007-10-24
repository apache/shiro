package org.jsecurity;

import java.security.Principal;
import java.io.Serializable;

public class UserIdPrincipal implements Principal, Serializable {


    private int userId;

    public UserIdPrincipal(int userId) {
        this.userId = userId;
    }

    public int getUserId() {
        return userId;
    }

    public String getName() {
        return String.valueOf(userId);
    }
}