package com.rsw.auth.domain;

import org.apache.commons.lang3.StringUtils;

/**
 *  for self administration of user account
 */
public class UserProfileUpdate extends UserProfile {

    private String oldPassword;
    private String newPassword;

    public UserProfileUpdate(String userName) {
        super(userName);
    }

    public String getOldPassword() {
        return oldPassword;
    }

    public UserProfileUpdate setOldPassword(String oldPassword) {
        this.oldPassword = oldPassword;
        return this;
    }

    public String getNewPassword() {
        return newPassword;
    }

    public UserProfileUpdate setNewPassword(String newPassword) {
        this.newPassword = newPassword;
        return this;
    }

    public boolean isChangePassword() {
        return ! StringUtils.isEmpty(oldPassword) && ! StringUtils.isEmpty(newPassword);
    }
}
