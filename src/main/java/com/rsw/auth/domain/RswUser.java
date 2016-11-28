package com.rsw.auth.domain;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;


/**
 * Enhances/extends Spring Security User object (UserDetails interface) to include a list of Groups,
 * a password expiry, name, email address and mobile number.
 *
 * NOTE: This User impl does not persist the "accountNonExpired" attribute - no use for it here.
 * The value of accountNonExpired in an object instance will always be true
 * This User impl replaces the binary "credentialsNonExpired" with a LocalDateTime "passwordExpiry", and
 * does not persist the boolean attribute.
 * The value of credentialsNonExpired is always set by comparing the passwordExpiry with current date/time
 *
 * @author DAlms
 *
 */
public class RswUser extends User {

    private LocalDateTime passwordExpiry;
    private List<RswGroup> groups = new ArrayList<>();
    private String firstName;
    private String lastName;
    private String middleInitial;
    private String emailAddress;
    private String mobileNumber;


    /**
     * loading a pre-existing user - groups handled separately
     * @param username
     * @param enabled
     * @param passwordExpiry
     * @param accountLocked
     * @param authorities
     */
    public RswUser(String username, String password, boolean enabled, LocalDateTime passwordExpiry,
                   boolean accountLocked, Collection<? extends GrantedAuthority> authorities) {
        super(username, password, enabled, true, isNotExpired(passwordExpiry), ! accountLocked, authorities);
        this.passwordExpiry = passwordExpiry;
    }

    /**
     * prep for a new (unpersisted) user
     * @param username
     * @param password
     * @param enabled
     * @param passwordExpiry
     * @param accountLocked
     * @param groups
     */
	public RswUser(String username, String password, boolean enabled, LocalDateTime passwordExpiry,
                   boolean accountLocked, List<RswGroup> groups) {
		super(username, password, enabled, true, isNotExpired(passwordExpiry), ! accountLocked,
                AuthorityUtils.NO_AUTHORITIES);
		this.passwordExpiry = passwordExpiry;
		setGroups(groups);
	}

	public LocalDateTime getPasswordExpiry() {
		return passwordExpiry;
	}

	public RswUser setPasswordExpiry(LocalDateTime passwordExpiry) {
		this.passwordExpiry = passwordExpiry;
		return this;
	}

	public List<RswGroup> getGroups() {
		return groups;
	}

	public RswUser setGroups(List<RswGroup> groups) {
		if (groups != null) {
            this.groups = groups;
        } else {
            this.groups.clear();
        }
        return this;
	}

    public String getFirstName() {
        return firstName;
    }

    public RswUser setFirstName(String firstName) {
        this.firstName = firstName;
        return this;
    }

    public String getLastName() {
        return lastName;
    }

    public RswUser setLastName(String lastName) {
        this.lastName = lastName;
        return this;
    }

    public String getMiddleInitial() {
        return middleInitial;
    }

    public RswUser setMiddleInitial(String middleInitial) {
        this.middleInitial = middleInitial;
        return this;
    }

    public String getEmailAddress() {
        return emailAddress;
    }

    public RswUser setEmailAddress(String emailAddress) {
        this.emailAddress = emailAddress;
        return this;
    }

    public String getMobileNumber() {
        return mobileNumber;
    }

    public RswUser setMobileNumber(String mobileNumber) {
        this.mobileNumber = mobileNumber;
        return this;
    }

    private static boolean isNotExpired(LocalDateTime passwordExpiry) {
        return (passwordExpiry == null || LocalDateTime.now().isBefore(passwordExpiry));
    }

}
