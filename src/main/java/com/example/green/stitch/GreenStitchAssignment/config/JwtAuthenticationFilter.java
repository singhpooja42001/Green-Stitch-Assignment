package com.example.green.stitch.GreenStitchAssignment.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final jwtService jwtservice;
    private UserDetailsService userDetailsService;

    public JwtAuthenticationFilter(jwtService jwtservice) {
        this.jwtservice = jwtservice;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    )  throws ServletException, IOException {

        //check Jwt token when user request a http in the jwtAuthenticationFilter
        //when we make call then we have to pass jwt auth token in the header.
        //we can get the header from request
        final String AuthHeader = request.getHeader("Authorization");
        final String jwt , userEmail;
        if(AuthHeader == null || !AuthHeader.startsWith("Bearer "))
        {
            filterChain.doFilter(request,response);
            return;
        }
        //jwt token if present will be after "Bearer "
        jwt = AuthHeader.substring(7);

        //We have to extract userEmail from jwtToken and validate if the user is present in the database or not.
        userEmail = jwtservice.extractUserName(jwt);

        if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() != null )
        {
            //if user is authenticated then no need to check again , we can directly pass it to dispatcher srvlet instead of validating from the database.
            //we will check if the email exist or not in the database.
            UserDetails userdetails = this.userDetailsService.loadUserByUsername(userEmail);
            if(jwtservice.isTokenValid(userdetails, jwt))
            {
                //update the SecurityContextHolder
                UsernamePasswordAuthenticationToken authToken  = new UsernamePasswordAuthenticationToken(userdetails,null,userdetails.getAuthorities());
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request,response);
    }
}
