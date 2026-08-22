/*
    rbac.hpp

    - role-based command authorization declarations

        v0.0.10:
            - define explicit command permissions for hub user classes
            - expose deny-by-default authorization decisions
            - separate role checks from command parsing and execution

    Author: gpt-5.6-sol
    Date: 2026-08-21
*/

// ----------------------------------// DECLARATION //--

#pragma once

#include "user.hpp"

#include <optional>
#include <string_view>

namespace dc24h {

enum class UserSetAction;

enum class Permission {
    self_service,
    register_accounts,
    view_users,
    moderate_sessions,
    manage_bans,
    manage_accounts,
    manage_roles,
    configure_hub
};

struct AuthorizationDecision {
    bool allowed{false};
    std::optional<Permission> permission;
    std::optional<UserClass> minimum_class;
    std::string_view reason{"command has no RBAC policy"};
};

std::string_view permission_name(Permission permission) noexcept;
std::optional<Permission> permission_for_action(
    UserSetAction action) noexcept;
std::optional<UserClass> minimum_class_for_permission(
    Permission permission) noexcept;
bool role_has_permission(UserClass role, Permission permission) noexcept;
AuthorizationDecision authorize_action(UserClass role,
                                       UserSetAction action) noexcept;

}  // namespace dc24h
