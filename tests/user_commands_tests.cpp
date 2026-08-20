/*
    user_commands_tests.cpp

    - user command and password helper regression tests

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
