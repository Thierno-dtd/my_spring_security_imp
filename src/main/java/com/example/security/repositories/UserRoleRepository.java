package com.example.security.repositories;

import com.example.security.entites.UserRole;
import com.example.security.entites.User;
import com.example.security.entites.Role;
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
public interface UserRoleRepository extends JpaRepository<UserRole, Long> {

    List<UserRole> findByUser(User user);

    List<UserRole> findByUserAndIsActiveTrue(User user);

    List<UserRole> findByRole(Role role);

    List<UserRole> findByRoleAndIsActiveTrue(Role role);

    Optional<UserRole> findByUserAndRole(User user, Role role);

    @Query("SELECT ur FROM UserRole ur " +
            "WHERE ur.user = :user AND ur.isActive = true " +
            "AND (ur.expiresAt IS NULL OR ur.expiresAt > :now)")
    List<UserRole> findEffectiveUserRoles(@Param("user") User user, @Param("now") LocalDateTime now);

    @Query("SELECT ur FROM UserRole ur " +
            "WHERE ur.expiresAt IS NOT NULL AND ur.expiresAt <= :now AND ur.isActive = true")
    List<UserRole> findExpiredUserRoles(@Param("now") LocalDateTime now);

    @Query("SELECT ur FROM UserRole ur " +
            "WHERE ur.user.id = :userId AND ur.role.name IN :roleNames AND ur.isActive = true")
    List<UserRole> findByUserIdAndRoleNames(@Param("userId") Long userId, @Param("roleNames") List<String> roleNames);

    @Query("SELECT COUNT(ur) FROM UserRole ur " +
            "WHERE ur.role.id = :roleId AND ur.isActive = true " +
            "AND (ur.expiresAt IS NULL OR ur.expiresAt > :now)")
    Long countEffectiveUsersByRole(@Param("roleId") Long roleId, @Param("now") LocalDateTime now);

    Page<UserRole> findByAssignedBy(String assignedBy, Pageable pageable);

    @Query("SELECT ur FROM UserRole ur " +
            "WHERE ur.assignedAt BETWEEN :startDate AND :endDate")
    List<UserRole> findByAssignedAtBetween(@Param("startDate") LocalDateTime startDate,
                                           @Param("endDate") LocalDateTime endDate);

    boolean existsByUserAndRole(User user, Role role);
}