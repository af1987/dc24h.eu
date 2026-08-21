/*
    user_commands_tests.cpp

    - user command and password helper regression tests

        v0.0.05:
            - test the complete registered-user administration key set
            - test class-0 default, password reset, +passwd and IP queries
            - reject temporary Master class above the Admin maximum

        v0.0.04:
            - test passwordless user registration parsing
            - verify new.id.password is distinct from change.id.password
            - test user-list-by-class command parsing

        v0.0.03:
            - test all supported numeric user classes
            - test new-user and password-change !set key parsing
            - test password values containing dots
            - test PBKDF2 password hash verification

    Author: gpt-5.6-sol
    Date: 2026-08-20
*/

// ----------------------------------// DECLARATION //--

#include "user_commands_tests.hpp"

#include "user.hpp"
#include "user_commands.hpp"

#include <array>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <string>

namespace dc24h::tests {

void run_user_command_tests() {
    constexpr std::array<std::int16_t, 8> classes{
        -1, 0, 1, 2, 3, 4, 5, 10};
    for (const std::int16_t value : classes) {
        assert(is_valid_user_class(value));
        assert(user_class_from_int(value).has_value());
    }
    assert(!is_valid_user_class(6));

    std::string error;

    const auto create =
        UserCommandProcessor::parse(
            "!set key.user.new.username.class.password=[alice.3.Strong.pass123]",
            error);
    assert(create.has_value());
    assert(create->action == UserSetAction::create_user);
    assert(create->username == "alice");
    assert(create->user_class == UserClass::operator_user);
    assert(create->password == "Strong.pass123");

    const auto create_without_password =
        UserCommandProcessor::parse(
            "!set key.user.new.username.class=[bob.1]",
            error);
    assert(create_without_password.has_value());
    assert(create_without_password->action ==
           UserSetAction::create_user_without_password);
    assert(create_without_password->username == "bob");
    assert(create_without_password->user_class == UserClass::registered);
    assert(create_without_password->password.empty());

    const auto change =
        UserCommandProcessor::parse(
            "!set key.user.change.id.password=[5.New.pass123]",
            error);
    assert(change.has_value());
    assert(change->action == UserSetAction::change_password_by_id);
    assert(change->user_id == 5U);
    assert(change->password == "New.pass123");

    const auto add =
        UserCommandProcessor::parse(
            "!set key.user.new.id.password=[5.Other.pass123]",
            error);
    assert(add.has_value());
    assert(add->action == UserSetAction::add_password_by_id);
    assert(add->user_id == 5U);
    assert(add->password == "Other.pass123");

    const auto list =
        UserCommandProcessor::parse(
            "!set key.user.info.userlist.class=[3]",
            error);
    assert(list.has_value());
    assert(list->action == UserSetAction::list_users_by_class);
    assert(list->user_class == UserClass::operator_user);

    const auto hublist =
        UserCommandProcessor::parse(
            "!set key.user.info.userlist.class=[-1]",
            error);
    assert(hublist.has_value());
    assert(hublist->user_class == UserClass::hublist_pinger);

    const auto default_class = UserCommandProcessor::parse(
        "!set key.user.info.userlist.class=[]", error);
    assert(default_class.has_value());
    assert(default_class->user_class == UserClass::regular);

    const auto reset_password = UserCommandProcessor::parse(
        "!set key.user.change.username.password=[alice.]", error);
    assert(reset_password.has_value());
    assert(reset_password->action ==
           UserSetAction::change_password_by_username);
    assert(reset_password->username == "alice");
    assert(reset_password->password.empty());

    const auto self_password = UserCommandProcessor::parse(
        "+passwd First.pass123", error);
    assert(self_password.has_value());
    assert(self_password->action == UserSetAction::self_add_password);

    const auto remove = UserCommandProcessor::parse(
        "!set key.user.remove.username=[alice]", error);
    assert(remove.has_value());
    assert(remove->action == UserSetAction::remove_user);

    const auto disable = UserCommandProcessor::parse(
        "!set key.user.disable.username=[alice]", error);
    assert(disable.has_value());
    assert(disable->action == UserSetAction::disable_user);

    const auto enable = UserCommandProcessor::parse(
        "!set key.user.enable.username=[alice]", error);
    assert(enable.has_value());
    assert(enable->action == UserSetAction::enable_user);

    const auto change_class = UserCommandProcessor::parse(
        "!set key.user.change.username.class=[alice.4]", error);
    assert(change_class.has_value());
    assert(change_class->action == UserSetAction::change_class);

    const auto temporary_class = UserCommandProcessor::parse(
        "!set key.user.change.username.class.temp=[alice.5]", error);
    assert(temporary_class.has_value());
    assert(temporary_class->action ==
           UserSetAction::change_class_temporarily);

    const auto invalid_temporary_master = UserCommandProcessor::parse(
        "!set key.user.change.username.class.temp=[alice.10]", error);
    assert(!invalid_temporary_master.has_value());
    assert(error == "temporary class maximum is Admin (5)");

    const auto info = UserCommandProcessor::parse(
        "!set key.user.info.username=[alice]", error);
    assert(info.has_value());
    assert(info->action == UserSetAction::show_user_info);

    const auto ip_host = UserCommandProcessor::parse(
        "!set key.user.info.ip.hostname.username=[alice]", error);
    assert(ip_host.has_value());
    assert(ip_host->action == UserSetAction::show_ip_and_hostname);

    const auto hostname = UserCommandProcessor::parse(
        "!set key.user.info.hostname.username=[alice]", error);
    assert(hostname.has_value());
    assert(hostname->action == UserSetAction::show_hostname);

    const auto by_ip = UserCommandProcessor::parse(
        "!set key.user.info.userlist.ip=[127.0.0.1]", error);
    assert(by_ip.has_value());
    assert(by_ip->action == UserSetAction::find_users_by_ip);

    const auto by_range = UserCommandProcessor::parse(
        "!set key.user.info.userlist.iprange=[10.0.0.1-10.0.0.20]", error);
    assert(by_range.has_value());
    assert(by_range->action == UserSetAction::find_users_by_ip_range);

    const auto by_subnet = UserCommandProcessor::parse(
        "!set key.user.info.userlist.subnet=[10.0.0.0/24]", error);
    assert(by_subnet.has_value());
    assert(by_subnet->action == UserSetAction::find_users_by_subnet);

    const auto invalid_class =
        UserCommandProcessor::parse(
            "!set key.user.new.username.class.password=[alice.6.StrongPass123]",
            error);
    assert(!invalid_class.has_value());
    assert(error == "invalid user class");

    const auto encoded = hash_password("StrongPass.123");
    assert(encoded.starts_with("pbkdf2-sha256$"));
    assert(verify_password("StrongPass.123", encoded));
    assert(!verify_password("WrongPass.123", encoded));
}

}  // namespace dc24h::tests

int main() {
    dc24h::tests::run_user_command_tests();
    std::cout << "user command tests passed\n";
    return 0;
}
