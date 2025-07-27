package com.example.security.logs;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Collections;
import java.util.regex.Pattern;

@Service
@Slf4j
public class IpAddressService {

    // Pattern pour valider les adresses IP privées
    private static final Pattern PRIVATE_IP_PATTERN = Pattern.compile(
            "^(127\\.)|(192\\.168\\.)|(10\\.)|(172\\.1[6-9]\\.)|(172\\.2[0-9]\\.)|(172\\.3[0-1]\\.)|(::1$)|([fF][cCdD])"
    );

    /**
     * Extraction intelligente de l'adresse IP client
     */
    public String getClientIpAddress(HttpServletRequest request) {
        String clientIp = null;

        // 1. Vérifier les headers de proxy/load balancer
        String[] headerNames = {
                "X-Forwarded-For",
                "X-Real-IP",
                "X-Client-IP",
                "CF-Connecting-IP",        // Cloudflare
                "True-Client-IP",          // Akamai
                "X-Cluster-Client-IP",     // Cluster
                "Proxy-Client-IP",
                "WL-Proxy-Client-IP"
        };

        for (String header : headerNames) {
            clientIp = request.getHeader(header);
            if (isValidIp(clientIp)) {
                // Si multiple IPs (proxy chain), prendre la première
                if (clientIp.contains(",")) {
                    clientIp = clientIp.split(",")[0].trim();
                }
                log.debug("IP trouvée via header {}: {}", header, clientIp);
                break;
            }
        }

        // 2. Fallback vers RemoteAddr
        if (!isValidIp(clientIp)) {
            clientIp = request.getRemoteAddr();
            log.debug("IP via RemoteAddr: {}", clientIp);
        }

        // 3. Si toujours localhost, essayer de deviner l'IP réseau
        if (isLocalhost(clientIp)) {
            String networkIp = guessNetworkIp();
            if (networkIp != null) {
                log.info("IP localhost détectée ({}), IP réseau devinée: {}", clientIp, networkIp);
                return formatIpInfo(clientIp, networkIp);
            }
        }

        return clientIp;
    }

    /**
     * Validation d'une adresse IP
     */
    private boolean isValidIp(String ip) {
        return ip != null &&
                !ip.isEmpty() &&
                !ip.equalsIgnoreCase("unknown") &&
                !ip.equalsIgnoreCase("null");
    }

    /**
     * Vérification si l'IP est localhost
     */
    private boolean isLocalhost(String ip) {
        return ip != null && (
                ip.equals("127.0.0.1") ||
                        ip.equals("0:0:0:0:0:0:0:1") ||
                        ip.equals("::1") ||
                        ip.startsWith("127.")
        );
    }

    /**
     * Deviner l'IP réseau de la machine
     */
    private String guessNetworkIp() {
        try {
            return Collections.list(NetworkInterface.getNetworkInterfaces())
                    .stream()
                    .flatMap(i -> Collections.list(i.getInetAddresses()).stream())
                    .filter(addr -> !addr.isLoopbackAddress() && addr.isSiteLocalAddress())
                    .findFirst()
                    .map(InetAddress::getHostAddress)
                    .orElse(null);
        } catch (Exception e) {
            log.warn("Impossible de deviner l'IP réseau: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Formatage avec informations supplémentaires
     */
    private String formatIpInfo(String originalIp, String networkIp) {
        return String.format("%s (réseau: %s)", originalIp, networkIp);
    }

    /**
     * Obtenir des informations détaillées sur l'IP
     */
    public IpInfo getDetailedIpInfo(HttpServletRequest request) {
        String clientIp = getClientIpAddress(request);
        String userAgent = request.getHeader("User-Agent");
        String referer = request.getHeader("Referer");

        return IpInfo.builder()
                .ipAddress(clientIp)
                .userAgent(userAgent)
                .referer(referer)
                .isLocalhost(isLocalhost(clientIp))
                .isPrivateNetwork(isPrivateNetwork(clientIp))
                .requestUri(request.getRequestURI())
                .method(request.getMethod())
                .build();
    }

    /**
     * Vérifier si IP fait partie d'un réseau privé
     */
    private boolean isPrivateNetwork(String ip) {
        if (ip == null) return false;
        return PRIVATE_IP_PATTERN.matcher(ip).find();
    }

    /**
     * Classe pour informations détaillées IP
     */
    @lombok.Data
    @lombok.Builder
    public static class IpInfo {
        private String ipAddress;
        private String userAgent;
        private String referer;
        private boolean isLocalhost;
        private boolean isPrivateNetwork;
        private String requestUri;
        private String method;

        @Override
        public String toString() {
            return String.format("IP: %s | Localhost: %s | Private: %s | UA: %s",
                    ipAddress, isLocalhost, isPrivateNetwork,
                    userAgent != null ? userAgent.substring(0, Math.min(50, userAgent.length())) : "N/A");
        }
    }
}