package com.example.security.repositories;

import com.example.security.entites.RoleExclusion;
import com.example.security.entites.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface RoleExclusionRepository extends JpaRepository<RoleExclusion, Long> {

    List<RoleExclusion> findByRole(Role role);

    List<RoleExclusion> findByRoleAndIsActiveTrue(Role role);

    List<RoleExclusion> findByExcludedRole(Role excludedRole);

    List<RoleExclusion> findByExcludedRoleAndIsActiveTrue(Role excludedRole);

    @Query("SELECT re.excludedRole FROM RoleExclusion re " +
            "WHERE re.role = :role AND re.isActive = true")
    List<Role> findExcludedRolesByRole(@Param("role") Role role);

    @Query("SELECT re.role FROM RoleExclusion re " +
            "WHERE re.excludedRole = :excludedRole AND re.isActive = true")
    List<Role> findRolesThatExclude(@Param("excludedRole") Role excludedRole);

    @Query("SELECT COUNT(re) > 0 FROM RoleExclusion re " +
            "WHERE ((re.role = :role1 AND re.excludedRole = :role2) " +
            "OR (re.role = :role2 AND re.excludedRole = :role1)) " +
            "AND re.isActive = true")
    boolean areRolesExclusive(@Param("role1") Role role1, @Param("role2") Role role2);

    boolean existsByRoleAndExcludedRole(Role role, Role excludedRole);
}