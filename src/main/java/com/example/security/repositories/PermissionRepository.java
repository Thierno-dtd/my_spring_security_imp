package com.example.security.repositories;

import com.example.security.entites.Permission;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface PermissionRepository extends JpaRepository<Permission, Long> {

    Optional<Permission> findByName(String name);

    List<Permission> findByIsActiveTrue();

    List<Permission> findByResource(String resource);

    List<Permission> findByAction(String action);

    List<Permission> findByResourceAndAction(String resource, String action);

    Page<Permission> findByNameContainingIgnoreCase(String name, Pageable pageable);

    Page<Permission> findByResourceContainingIgnoreCase(String resource, Pageable pageable);

    @Query("SELECT p FROM Permission p WHERE p.isSystem = false")
    List<Permission> findNonSystemPermissions();

    @Query("SELECT DISTINCT p.resource FROM Permission p WHERE p.isActive = true ORDER BY p.resource")
    List<String> findAllActiveResources();

    @Query("SELECT DISTINCT p.action FROM Permission p WHERE p.isActive = true ORDER BY p.action")
    List<String> findAllActiveActions();

    @Query("SELECT p FROM Permission p " +
            "JOIN p.roles r " +
            "WHERE r.id = :roleId AND p.isActive = true AND r.isActive = true")
    List<Permission> findByRoleId(@Param("roleId") Long roleId);

    boolean existsByName(String name);

    boolean existsByResourceAndAction(String resource, String action);
}
