package com.example.security.repositories;

import com.example.security.entites.UserRoleGroup;
import com.example.security.entites.User;
import com.example.security.entites.RoleGroup;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserRoleGroupRepository extends JpaRepository<UserRoleGroup, Long> {

    List<UserRoleGroup> findByUser(User user);

    List<UserRoleGroup> findByUserAndIsActiveTrue(User user);

    List<UserRoleGroup> findByRoleGroup(RoleGroup roleGroup);

    List<UserRoleGroup> findByRoleGroupAndIsActiveTrue(RoleGroup roleGroup);

    Optional<UserRoleGroup> findByUserAndRoleGroup(User user, RoleGroup roleGroup);

    @Query("SELECT urg FROM UserRoleGroup urg " +
            "WHERE urg.user = :user AND urg.isActive = true " +
            "AND (urg.expiresAt IS NULL OR urg.expiresAt > :now)")
    List<UserRoleGroup> findEffectiveUserRoleGroups(@Param("user") User user, @Param("now") LocalDateTime now);

    @Query("SELECT urg FROM UserRoleGroup urg " +
            "WHERE urg.expiresAt IS NOT NULL AND urg.expiresAt <= :now AND urg.isActive = true")
    List<UserRoleGroup> findExpiredUserRoleGroups(@Param("now") LocalDateTime now);

    Page<UserRoleGroup> findByAssignedBy(String assignedBy, Pageable pageable);

    boolean existsByUserAndRoleGroup(User user, RoleGroup roleGroup);
}