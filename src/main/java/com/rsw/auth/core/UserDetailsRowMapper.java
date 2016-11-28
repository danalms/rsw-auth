package com.rsw.auth.core;

import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.core.userdetails.UserDetails;

import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Created by DAlms on 11/26/16.
 */
public class UserDetailsRowMapper implements RowMapper<UserDetails> {
    private RswUserRowMapper userRowMapper = new RswUserRowMapper();
    @Override
    public UserDetails mapRow(ResultSet rs, int rowNum) throws SQLException {
        return userRowMapper.mapRow(rs, rowNum);
    }
}
