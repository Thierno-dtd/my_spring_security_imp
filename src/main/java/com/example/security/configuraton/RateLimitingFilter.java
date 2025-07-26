package com.example.security.configuraton;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Component
public class RateLimitingFilter implements Filter {

    private static final AtomicInteger blockedRequests = new AtomicInteger(0);
    private static final AtomicInteger totalRequests = new AtomicInteger(0);

    @Value("${app.security.rate-limit.max-requests}")
    private int maxRequests;

    @Value("${app.security.rate-limit.time-window}")
    private long timeWindow;

    private final Map<String, List<Long>> requestCounts = new ConcurrentHashMap<>();

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String clientIP = httpRequest.getRemoteAddr();

        if (httpRequest.getRequestURI().contains("/auth/")) {
            // LOG AJOUTÉ

            if (isRateLimited(clientIP)) {
                // LOG AJOUTÉ
                HttpServletResponse httpResponse = (HttpServletResponse) response;
                httpResponse.setStatus(429);
                httpResponse.setContentType("application/json");
                httpResponse.getWriter().write("{\"error\":\"Trop de tentatives. Réessayez plus tard.\"}");
                return;
            }
            System.out.println("✅ IP autorisée: " + clientIP); // LOG AJOUTÉ
        }
        chain.doFilter(request, response);
    }

    private boolean isRateLimited(String clientIP) {
        long currentTime = System.currentTimeMillis();
        requestCounts.putIfAbsent(clientIP, new ArrayList<>());

        List<Long> requests = requestCounts.get(clientIP);
        requests.removeIf(time -> currentTime - time > timeWindow);

        if (requests.size() >= maxRequests) {
            blockedRequests.incrementAndGet();
            System.out.println("🚫 Total requêtes bloquées: " + blockedRequests.get());
            return true;
        }

        totalRequests.incrementAndGet();

        requests.add(currentTime);
        return false;
    }


}
