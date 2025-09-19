package com.example.security.repositories;

import com.example.security.entites.Role;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.Set;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {

    Optional<Role> findByName(String name);

    List<Role> findByIsActiveTrue();

    List<Role> findByCategory(String category);

    List<Role> findByCategoryAndIsActiveTrue(String category);

    Page<Role> findByNameContainingIgnoreCase(String name, Pageable pageable);

    Page<Role> findByIsActive(Boolean isActive, Pageable pageable);

    @Query("SELECT r FROM Role r WHERE r.isSystem = false")
    List<Role> findNonSystemRoles();

    @Query("SELECT r FROM Role r WHERE r.isSystem = true")
    List<Role> findSystemRoles();

    @Query("SELECT r FROM Role r WHERE r.priority >= :minPriority ORDER BY r.priority DESC")
    List<Role> findByPriorityGreaterThanEqual(@Param("minPriority") Integer minPriority);

    @Query("SELECT DISTINCT r FROM Role r " +
            "LEFT JOIN r.roleGroups rg " +
            "WHERE r.isActive = true AND (rg.isActive = true OR rg IS NULL)")
    List<Role> findActiveRolesWithActiveGroups();

    @Query("SELECT r FROM Role r " +
            "WHERE r.id NOT IN (" +
            "   SELECT re.excludedRole.id FROM RoleExclusion re " +
            "   WHERE re.role.id = :roleId AND re.isActive = true" +
            ")")
    List<Role> findNonExcludedRoles(@Param("roleId") Long roleId);

    @Query("SELECT COUNT(ur) FROM UserRole ur WHERE ur.role.id = :roleId AND ur.isActive = true")
    Long countActiveUsersByRole(@Param("roleId") Long roleId);

    boolean existsByName(String name);
}
