package com.Security.security.filter;

import com.Security.security.ServiceLayer.customUserDetailService;
import com.Security.security.jwtUtility.jwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class securityFilter extends OncePerRequestFilter {
    @Autowired
    private jwtUtil jutil;
    @Autowired
    private customUserDetailService c;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        System.out.println("inside Filter Class");
        String token = null;
        String username = null;
        String HeaderAuthorization = request.getHeader("Authorization");
        if (HeaderAuthorization != null && HeaderAuthorization.startsWith("Bearer")) {
            System.out.println("inside 1st if in Filter Class");

            token = HeaderAuthorization.substring(7);
            username = jutil.getUsernameFromToken(token);

        }

        if (null != username && SecurityContextHolder.getContext().getAuthentication() == null) {
            System.out.println("inside 2nd if in Filter Class");
            UserDetails userDetails = c.loadUserByUsername(username);
            if (jutil.validateToken(token, userDetails)) {
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                        new UsernamePasswordAuthenticationToken(username, null, userDetails.getAuthorities());
                usernamePasswordAuthenticationToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }


        }
        filterChain.doFilter(request, response);
    }
}