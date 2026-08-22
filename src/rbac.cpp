/*
    rbac.cpp

    - role-based command authorization implementation

        v0.0.10:
            - map every known hub command to one explicit permission
            - implement hierarchical class permissions with least privilege
            - deny unknown actions and roles by default

    Author: gpt-5.6-sol
    Date: 2026-08-21
*/

// ----------------------------------// DECLARATION //--

#include "rbac.hpp"

#include "user_commands.hpp"

#include <cstdint>

namespace dc24h {

std::string_view permission_name(Permission permission) noexcept {
    switch (permission) {
        case Permission::self_service: return "self_service";
        case Permission::register_accounts: return "register_accounts";
        case Permission::view_users: return "view_users";
        case Permission::moderate_sessions: return "moderate_sessions";
        case Permission::manage_bans: return "manage_bans";
        case Permission::manage_accounts: return "manage_accounts";
        case Permission::manage_roles: return "manage_roles";
        case Permission::configure_hub: return "configure_hub";
    }
    return "unknown";
}

std::optional<Permission> permission_for_action(
    UserSetAction action) noexcept {
    switch (action) {
        case UserSetAction::self_add_password:
        case UserSetAction::self_register:
        case UserSetAction::set_self_visibility:
            return Permission::self_service;

        case UserSetAction::create_user:
        case UserSetAction::create_user_without_password:
            return Permission::register_accounts;

        case UserSetAction::list_users_by_class:
        case UserSetAction::show_user_info:
        case UserSetAction::show_ip_and_hostname:
        case UserSetAction::show_hostname:
        case UserSetAction::find_users_by_ip:
        case UserSetAction::find_users_by_ip_range:
        case UserSetAction::find_users_by_subnet:
        case UserSetAction::show_kick_info:
        case UserSetAction::show_ban_info:
        case UserSetAction::list_bans:
        case UserSetAction::list_kicks:
            return Permission::view_users;

        case UserSetAction::disconnect_user:
        case UserSetAction::kick_user:
            return Permission::moderate_sessions;

        case UserSetAction::create_ban:
        case UserSetAction::revoke_kick:
        case UserSetAction::revoke_ban:
            return Permission::manage_bans;

        case UserSetAction::add_password_by_id:
        case UserSetAction::change_password_by_id:
        case UserSetAction::change_password_by_username:
        case UserSetAction::remove_user:
        case UserSetAction::disable_user:
        case UserSetAction::enable_user:
        case UserSetAction::set_kick_protection:
        case UserSetAction::set_hide_share:
        case UserSetAction::set_hide_operator_key:
        case UserSetAction::set_user_note:
        case UserSetAction::set_timed_policy:
        case UserSetAction::remove_timed_policy:
        case UserSetAction::set_auth_ip:
        case UserSetAction::remove_auth_ip:
        case UserSetAction::set_email:
        case UserSetAction::set_public_note:
        case UserSetAction::set_hide_kick:
        case UserSetAction::set_hide_kick_class:
            return Permission::manage_accounts;

        case UserSetAction::change_class:
        case UserSetAction::change_class_temporarily:
            return Permission::manage_roles;

        case UserSetAction::set_hub_setting:
            return Permission::configure_hub;
    }
    return std::nullopt;
}

std::optional<UserClass> minimum_class_for_permission(
    Permission permission) noexcept {
    switch (permission) {
        case Permission::self_service: return UserClass::regular;
        case Permission::register_accounts: return UserClass::operator_user;
        case Permission::view_users:
        case Permission::moderate_sessions:
            return UserClass::operator_user;
        case Permission::manage_bans:
        case Permission::manage_accounts:
            return UserClass::admin;
        case Permission::manage_roles:
        case Permission::configure_hub:
            return UserClass::master;
    }
    return std::nullopt;
}

bool role_has_permission(UserClass role, Permission permission) noexcept {
    const auto minimum = minimum_class_for_permission(permission);
    if (!minimum.has_value()) return false;
    return static_cast<std::int16_t>(role) >=
        static_cast<std::int16_t>(*minimum);
}

AuthorizationDecision authorize_action(UserClass role,
                                       UserSetAction action) noexcept {
    const auto permission = permission_for_action(action);
    if (!permission.has_value()) return {};
    const auto minimum = minimum_class_for_permission(*permission);
    if (!minimum.has_value()) return {false, permission, std::nullopt,
                                     "permission has no role policy"};
    if (!role_has_permission(role, *permission)) {
        return {false, permission, minimum,
                "role does not grant the required permission"};
    }
    return {true, permission, minimum, "authorized by role"};
}

}  // namespace dc24h
