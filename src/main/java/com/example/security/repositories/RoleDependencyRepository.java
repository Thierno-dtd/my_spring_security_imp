package com.example.security.repositories;

import com.example.security.entites.RoleDependency;
import com.example.security.entites.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface RoleDependencyRepository extends JpaRepository<RoleDependency, Long> {

    List<RoleDependency> findByRole(Role role);

    List<RoleDependency> findByRoleAndIsActiveTrue(Role role);

    List<RoleDependency> findByRequiredRole(Role requiredRole);

    List<RoleDependency> findByRequiredRoleAndIsActiveTrue(Role requiredRole);

    List<RoleDependency> findByDependencyType(String dependencyType);

    @Query("SELECT rd.requiredRole FROM RoleDependency rd " +
            "WHERE rd.role = :role AND rd.isActive = true")
    List<Role> findRequiredRolesByRole(@Param("role") Role role);

    @Query("SELECT rd.role FROM RoleDependency rd " +
            "WHERE rd.requiredRole = :requiredRole AND rd.isActive = true")
    List<Role> findRolesThatRequire(@Param("requiredRole") Role requiredRole);

    @Query("SELECT COUNT(rd) > 0 FROM RoleDependency rd " +
            "WHERE rd.role = :role AND rd.requiredRole = :requiredRole " +
            "AND rd.isActive = true")
    boolean hasRoleDependency(@Param("role") Role role, @Param("requiredRole") Role requiredRole);

    boolean existsByRoleAndRequiredRole(Role role, Role requiredRole);
}