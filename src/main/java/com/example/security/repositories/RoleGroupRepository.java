package com.example.security.repositories;

import com.example.security.entites.RoleGroup;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface RoleGroupRepository extends JpaRepository<RoleGroup, Long> {

    Optional<RoleGroup> findByName(String name);

    List<RoleGroup> findByIsActiveTrue();

    List<RoleGroup> findByIsDefaultTrue();

    Page<RoleGroup> findByNameContainingIgnoreCase(String name, Pageable pageable);

    Page<RoleGroup> findByIsActive(Boolean isActive, Pageable pageable);

    @Query("SELECT rg FROM RoleGroup rg " +
            "JOIN rg.roles r " +
            "WHERE r.id = :roleId AND rg.isActive = true")
    List<RoleGroup> findByRoleId(@Param("roleId") Long roleId);

    @Query("SELECT COUNT(urg) FROM UserRoleGroup urg " +
            "WHERE urg.roleGroup.id = :roleGroupId AND urg.isActive = true")
    Long countActiveUsersByRoleGroup(@Param("roleGroupId") Long roleGroupId);

    @Query("SELECT rg FROM RoleGroup rg " +
            "JOIN rg.userRoleGroups urg " +
            "WHERE urg.user.id = :userId AND urg.isActive = true AND rg.isActive = true")
    List<RoleGroup> findActiveRoleGroupsByUserId(@Param("userId") Long userId);

    boolean existsByName(String name);
}