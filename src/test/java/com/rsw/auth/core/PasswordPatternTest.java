package com.rsw.auth.core;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Test;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PasswordPatternTest {

    @Test
    public void passwordPattern() {
        Pattern pat = Pattern.compile("^[a-zA-Z0-9!@#$%\\^\\-_+=]{6,15}$");
        Matcher mat = pat.matcher("12345");
    	assertFalse(mat.matches());
        mat = pat.matcher("123456");
    	assertTrue(mat.matches());
        mat = pat.matcher("1234567890abcde");
    	assertTrue(mat.matches());
        mat = pat.matcher("1234567890abcdef");
    	assertFalse(mat.matches());

        pat = Pattern.compile("^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%\\^\\-_+=])[a-zA-Z0-9!@#$%\\^\\-_+=]{6,15}$");
        mat = pat.matcher("a1C#ef");
    	assertTrue(mat.matches());

        // This password from Drew
        mat = pat.matcher("1Gueuze!");
        assertTrue(mat.matches());

        mat = pat.matcher("1Gueuze^");
        assertTrue(mat.matches());

        mat = pat.matcher("1Gueuze-");
        assertTrue(mat.matches());

        mat = pat.matcher("1Gueuze_");
        assertTrue(mat.matches());

        mat = pat.matcher("1Gueuze!");
        assertTrue(mat.matches());

        mat = pat.matcher("1Gueuze@");
        assertTrue(mat.matches());

        mat = pat.matcher("1Gueuze#");
        assertTrue(mat.matches());

        mat = pat.matcher("1Gueuze$");
        assertTrue(mat.matches());

        mat = pat.matcher("1Gueuze%");
        assertTrue(mat.matches());

        mat = pat.matcher("1Gueuze+");
        assertTrue(mat.matches());

        mat = pat.matcher("1Gueuze=");
        assertTrue(mat.matches());

        mat = pat.matcher("1gueuze!");
        assertFalse(mat.matches());

	}

}
