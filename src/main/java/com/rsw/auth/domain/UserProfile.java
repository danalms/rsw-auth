package com.rsw.auth.domain;

import javax.validation.constraints.NotNull;

/**
 *  for viewing or self-updating user profile
 */
public class UserProfile {

    @NotNull
    private String userName;
    @NotNull
	private String firstName;
	private String middleInitial;
    @NotNull
	private String lastName;
    @NotNull
    private String emailAddress;
    private String mobileNumber;

    public UserProfile(String userName) {
        this.userName = userName;
    }

    public String getUserName() {
        return userName;
    }

    public UserProfile setUserName(String userName) {
        this.userName = userName;
        return this;
    }

    public String getFirstName() {
        return firstName;
    }

    public UserProfile setFirstName(String firstName) {
        this.firstName = firstName;
        return this;
    }

    public String getMiddleInitial() {
        return middleInitial;
    }

    public UserProfile setMiddleInitial(String middleInitial) {
        this.middleInitial = middleInitial;
        return this;
    }

    public String getLastName() {
        return lastName;
    }

    public UserProfile setLastName(String lastName) {
        this.lastName = lastName;
        return this;
    }

    public String getEmailAddress() {
        return emailAddress;
    }

    public UserProfile setEmailAddress(String emailAddress) {
        this.emailAddress = emailAddress;
        return this;
    }

    public String getMobileNumber() {
        return mobileNumber;
    }

    public UserProfile setMobileNumber(String mobileNumber) {
        this.mobileNumber = mobileNumber;
        return this;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof UserProfile)) {
            return false;
        }

        UserProfile that = (UserProfile) o;

        if (!userName.equals(that.userName)) {
            return false;
        }
        if (!firstName.equals(that.firstName)) {
            return false;
        }
        if (middleInitial != null ? !middleInitial.equals(that.middleInitial) : that.middleInitial != null) {
            return false;
        }
        if (!lastName.equals(that.lastName)) {
            return false;
        }
        return emailAddress.equals(that.emailAddress);
    }

    @Override
    public int hashCode() {
        int result = userName.hashCode();
        result = 31 * result + firstName.hashCode();
        result = 31 * result + (middleInitial != null ? middleInitial.hashCode() : 0);
        result = 31 * result + lastName.hashCode();
        result = 31 * result + emailAddress.hashCode();
        return result;
    }
}
