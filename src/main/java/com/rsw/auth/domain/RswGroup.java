package com.rsw.auth.domain;

/**
 * Security group names for this application. These names are pre-loaded in the Spring Security
 * groups table, along with group_authorities to map to authorities.
 *
 * @author DAlms
 *
 */
public enum RswGroup {
    API_USER,
    API_ADMIN,
    SYSTEM_ADMIN
}
