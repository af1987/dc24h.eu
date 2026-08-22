/*
    user_commands_tests.cpp

    v0.0.10:
        - verify tagged MD5 defaults and PBKDF2 compatibility
        - verify deny-by-default RBAC class/permission mappings
        - verify exact and wildcard hostname ban matching

    - user command and password helper regression tests

        v0.0.08:
            - test key.kicks and key.bans values and operation namespaces
            - test all target matchers, duration boundaries and UTF-8 nicknames

        v0.0.07:
            - test every class, nickname and auto-registration setting key
            - test +regme and account profile/security keys
            - test nickname length, characters and prefix validation

        v0.0.06:
            - test moderation, visibility, notes and live disconnect/kick keys
            - test all timed restriction and delegated-privilege defaults
            - validate explicit duration parsing and invalid flags

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
    Date: 2026-08-21
*/

// ----------------------------------// DECLARATION //--

#include "user_commands_tests.hpp"

#include "hub_settings.hpp"
#include "moderation.hpp"
#include "rbac.hpp"
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

    const auto disconnect = UserCommandProcessor::parse(
        "!set key.user.disconnect.username=[alice]", error);
    assert(disconnect.has_value());
    assert(disconnect->action == UserSetAction::disconnect_user);

    const auto kick = UserCommandProcessor::parse(
        "!set key.user.kick.username=[alice]", error);
    assert(kick.has_value());
    assert(kick->action == UserSetAction::kick_user);

    const auto protect = UserCommandProcessor::parse(
        "!set key.user.protect.username.class=[alice.4]", error);
    assert(protect.has_value());
    assert(protect->action == UserSetAction::set_kick_protection);
    assert(protect->user_class == UserClass::cheef);

    const auto hide_share = UserCommandProcessor::parse(
        "!set key.user.hide.share.username=[alice.1]", error);
    assert(hide_share.has_value());
    assert(hide_share->action == UserSetAction::set_hide_share);
    assert(hide_share->enabled);

    const auto hide_operator = UserCommandProcessor::parse(
        "!set key.user.hide.operator.username=[alice.0]", error);
    assert(hide_operator.has_value());
    assert(hide_operator->action == UserSetAction::set_hide_operator_key);
    assert(!hide_operator->enabled);

    const auto note = UserCommandProcessor::parse(
        "!set key.user.note.username=[alice.Trusted local operator]", error);
    assert(note.has_value());
    assert(note->action == UserSetAction::set_user_note);
    assert(note->note == "Trusted local operator");

    const auto self_visibility = UserCommandProcessor::parse(
        "!set key.user.self.hide.class=[3]", error);
    assert(self_visibility.has_value());
    assert(self_visibility->action == UserSetAction::set_self_visibility);
    assert(self_visibility->user_class == UserClass::operator_user);

    struct TimedCase {
        const char* command;
        const char* policy;
        std::uint64_t default_seconds;
    };
    constexpr std::array<TimedCase, 9> timed_cases{{
        {"!set key.user.restrict.gag.username.time=[alice]", "gag", 604800U},
        {"!set key.user.restrict.download.username.time=[alice]", "no_download", 172800U},
        {"!set key.user.restrict.chat.username.time=[alice]", "no_chat", 172800U},
        {"!set key.user.restrict.pm.username.time=[alice]", "no_pm", 604800U},
        {"!set key.user.restrict.search.username.time=[alice]", "no_search", 604800U},
        {"!set key.user.grant.kick.username.time=[alice]", "can_kick", 604800U},
        {"!set key.user.grant.hideshare.username.time=[alice]", "hide_share", 604800U},
        {"!set key.user.grant.register.username.time=[alice]", "can_register", 604800U},
        {"!set key.user.grant.opchat.username.time=[alice]", "opchat", 604800U}
    }};
    for (const auto& test : timed_cases) {
        const auto parsed = UserCommandProcessor::parse(test.command, error);
        assert(parsed.has_value());
        assert(parsed->action == UserSetAction::set_timed_policy);
        assert(parsed->policy_key == test.policy);
        assert(parsed->duration_seconds == test.default_seconds);
    }

    const auto explicit_duration = UserCommandProcessor::parse(
        "!set key.user.restrict.gag.username.time=[alice.12h]", error);
    assert(explicit_duration.has_value());
    assert(explicit_duration->duration_seconds == 43200U);

    const auto remove_gag = UserCommandProcessor::parse(
        "!set key.user.restrict.gag.remove.username=[alice]", error);
    assert(remove_gag.has_value());
    assert(remove_gag->action == UserSetAction::remove_timed_policy);
    assert(remove_gag->policy_key == "gag");

    const auto regme = UserCommandProcessor::parse(
        "+regme SelfPass123", error);
    assert(regme.has_value());
    assert(regme->action == UserSetAction::self_register);

    const auto prefixed_auth_ip = UserCommandProcessor::parse(
        "!set key.user.auth.ip.username=[[AUTO]tester.127.0.0.1]", error);
    assert(prefixed_auth_ip.has_value());
    assert(prefixed_auth_ip->username == "[AUTO]tester");

    constexpr std::array<const char*, 30> setting_commands{{
        "!set key.kicks=[300]",
        "!set key.bans=[31536000]",
        "!set key.class.permission.register.difference=[2]",
        "!set key.class.permission.kick.difference=[0]",
        "!set key.class.permission.pm.difference=[10]",
        "!set key.class.permission.download.difference=[10]",
        "!set key.class.minimum.usehub=[0]",
        "!set key.class.minimum.usehub.passive=[0]",
        "!set key.class.minimum.register=[3]",
        "!set key.class.minimum.redirect=[3]",
        "!set key.class.minimum.broadcast=[3]",
        "!set key.class.minimum.broadcast.guests=[3]",
        "!set key.class.minimum.broadcast.registered=[3]",
        "!set key.class.minimum.broadcast.vip=[3]",
        "!set key.class.minimum.plugin.modify=[5]",
        "!set key.class.minimum.topic.modify=[5]",
        "!set key.class.minimum.trigger.modify=[5]",
        "!set key.nick.length.maximum=[32]",
        "!set key.nick.length.minimum=[3]",
        "!set key.nick.characters.allowed=[abcdefghijklmnopqrstuvwxyz]",
        "!set key.nick.prefix=[[EU]]",
        "!set key.nick.prefix.nocase=[1]",
        "!set key.nick.prefix.autoreg=[[AUTO]]",
        "!set key.nick.prefix.country=[[US]]",
        "!set key.user.autoreg.class=[1]",
        "!set key.user.autoreg.minimum.share.registered=[1024]",
        "!set key.user.autoreg.minimum.share.vip=[2048]",
        "!set key.user.autoreg.minimum.share.operator=[4096]",
        "!set key.user.password.minimum.length=[10]",
        "!set key.user.password.initial.timeout=[300]"
    }};
    for (const auto* command : setting_commands) {
        const auto setting = UserCommandProcessor::parse(command, error);
        assert(setting.has_value());
        assert(setting->action == UserSetAction::set_hub_setting);
        assert(!setting->setting_key.empty());
    }

    const auto timeout_alias = UserCommandProcessor::parse(
        "!set key.account.password.setup.timeout=[600]", error);
    assert(timeout_alias.has_value());
    assert(timeout_alias->setting_value == "600");

    const auto auth_ip = UserCommandProcessor::parse(
        "!set key.user.auth.ip.username=[alice.127.0.0.1]", error);
    assert(auth_ip.has_value());
    assert(auth_ip->action == UserSetAction::set_auth_ip);
    assert(auth_ip->query == "127.0.0.1");

    const auto remove_auth_ip = UserCommandProcessor::parse(
        "!set key.user.auth.ip.remove.username=[alice]", error);
    assert(remove_auth_ip.has_value());
    assert(remove_auth_ip->action == UserSetAction::remove_auth_ip);

    const auto email = UserCommandProcessor::parse(
        "!set key.user.email.username=[alice.alice@example.com]", error);
    assert(email.has_value());
    assert(email->action == UserSetAction::set_email);

    const auto public_note = UserCommandProcessor::parse(
        "!set key.user.note.public.username=[alice.Visible note]", error);
    assert(public_note.has_value());
    assert(public_note->action == UserSetAction::set_public_note);

    const auto hide_kick = UserCommandProcessor::parse(
        "!set key.user.hide.kick.username=[alice.1]", error);
    assert(hide_kick.has_value());
    assert(hide_kick->action == UserSetAction::set_hide_kick);

    const auto hide_kick_class = UserCommandProcessor::parse(
        "!set key.user.hide.kick.username.class=[alice.3]", error);
    assert(hide_kick_class.has_value());
    assert(hide_kick_class->action == UserSetAction::set_hide_kick_class);

    const auto kick_entry = UserCommandProcessor::parse(
        "!set key.kicks.add=[Alice.User|2w|Forbidden share]", error);
    assert(kick_entry.has_value());
    assert(kick_entry->action == UserSetAction::kick_user);
    assert(kick_entry->username == "Alice.User");
    assert(kick_entry->duration_seconds == 1209600U);
    assert(kick_entry->moderation_reason == "Forbidden share");

    const auto default_kick = UserCommandProcessor::parse(
        "!set key.kicks.add=[alice|Read the rules]", error);
    assert(default_kick.has_value());
    assert(default_kick->duration_seconds == 0U);

    const auto ban_entry = UserCommandProcessor::parse(
        "!set key.bans.add=[range|192.0.2.77/24|1M|Repeated abuse]",
        error);
    assert(ban_entry.has_value());
    assert(ban_entry->action == UserSetAction::create_ban);
    assert(ban_entry->moderation_target.kind ==
           ModerationTargetKind::ipv4_range);
    assert(ban_entry->moderation_target.value == "192.0.2.0");
    assert(ban_entry->moderation_target.secondary_value == "192.0.2.255");
    assert(ban_entry->duration_seconds == 2592000U);

    const auto permanent_ban = UserCommandProcessor::parse(
        "!set key.bans.add=[nick|blocked-user|permanent|Repeated abuse]",
        error);
    assert(permanent_ban.has_value());
    assert(permanent_ban->duration_seconds == 0U);

    const auto revoke_ban = UserCommandProcessor::parse(
        "!set key.bans.remove=[42|Appeal accepted]", error);
    assert(revoke_ban.has_value());
    assert(revoke_ban->action == UserSetAction::revoke_ban);
    assert(revoke_ban->moderation_id == 42U);

    const auto ban_info = UserCommandProcessor::parse(
        "!set key.bans.info=[42]", error);
    assert(ban_info.has_value());
    assert(ban_info->action == UserSetAction::show_ban_info);

    const auto ban_list = UserCommandProcessor::parse(
        "!set key.bans.list=[20]", error);
    assert(ban_list.has_value());
    assert(ban_list->action == UserSetAction::list_bans);
    const auto kick_list = UserCommandProcessor::parse(
        "!set key.kicks.list=[20]", error);
    assert(kick_list.has_value());
    assert(kick_list->action == UserSetAction::list_kicks);
    const auto revoke_kick = UserCommandProcessor::parse(
        "!set key.kicks.remove=[41|Entered in error]", error);
    assert(revoke_kick.has_value());
    assert(revoke_kick->action == UserSetAction::revoke_kick);
    assert(revoke_kick->moderation_id == 41U);
    const auto kick_info = UserCommandProcessor::parse(
        "!set key.kicks.info=[41]", error);
    assert(kick_info.has_value());
    assert(kick_info->action == UserSetAction::show_kick_info);

    HubSettings settings;
    assert(settings.kick_rejoin_delay_seconds == 300U);
    assert(settings.maximum_temporary_ban_seconds == 31536000U);
    const auto kick_setting = normalize_hub_setting("key.kicks", "600", error);
    assert(kick_setting.has_value());
    assert(apply_hub_setting(settings, "key.kicks", *kick_setting));
    assert(settings.kick_rejoin_delay_seconds == 600U);
    assert(!normalize_hub_setting("key.kicks", "59", error).has_value());
    assert(normalize_hub_setting("key.kicks", "86400", error).has_value());
    assert(normalize_hub_setting("key.bans", "60", error).has_value());
    assert(!normalize_hub_setting("key.bans", "31536001", error).has_value());

    const auto range = normalize_ban_target(
        "range", "198.51.100.10..198.51.100.20", error);
    assert(range.has_value());
    assert(moderation_target_matches(
        *range, "user", "", "198.51.100.10", std::nullopt));
    assert(moderation_target_matches(
        *range, "user", "", "198.51.100.20", std::nullopt));
    assert(!moderation_target_matches(
        *range, "user", "", "198.51.100.21", std::nullopt));
    const auto prefix = normalize_ban_target("prefix", "Bot-", error);
    assert(prefix.has_value());
    assert(moderation_target_matches(
        *prefix, "bot-123", "", "127.0.0.1", std::nullopt));
    const auto nickname = normalize_ban_target("nick", "Alice", error);
    assert(nickname.has_value());
    assert(moderation_target_matches(
        *nickname, "alice", "", "127.0.0.1", std::nullopt));
    const auto ipv4 = normalize_ban_target("ip", "203.0.113.9", error);
    assert(ipv4.has_value());
    assert(moderation_target_matches(
        *ipv4, "user", "", "203.0.113.9", std::nullopt));
    assert(!moderation_target_matches(
        *ipv4, "user", "", "203.0.113.10", std::nullopt));
    constexpr std::string_view cid_value =
        "W6AIUW3CLDF6OGHNVE4JPDDJ2P74IWRCF2O36TA";
    const auto cid = normalize_ban_target("cid", cid_value, error);
    assert(cid.has_value());
    assert(moderation_target_matches(
        *cid, "user", cid_value, "127.0.0.1", std::nullopt));
    const auto share_target = normalize_ban_target("share", "4096", error);
    assert(share_target.has_value());
    assert(moderation_target_matches(
        *share_target, "user", "", "127.0.0.1", 4096U));
    const ModerationTarget identity{
        ModerationTargetKind::identity, "Alice", std::string(cid_value)};
    assert(moderation_target_matches(
        identity, "alice", "", "127.0.0.1", std::nullopt));
    assert(moderation_target_matches(
        identity, "other", cid_value, "127.0.0.1", std::nullopt));
    assert(!moderation_target_matches(
        identity, "other", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "127.0.0.1", std::nullopt));

    const auto host = normalize_ban_target(
        "host", "CLIENT.Example.COM", error);
    assert(host.has_value());
    assert(host->kind == ModerationTargetKind::hostname);
    assert(host->value == "client.example.com");
    assert(moderation_target_matches(
        *host, "user", "", "203.0.113.4", std::nullopt,
        "client.example.com"));
    assert(!moderation_target_matches(
        *host, "user", "", "203.0.113.4", std::nullopt,
        "other.example.com"));
    const auto wildcard_host = normalize_ban_target(
        "host", "*.example.com", error);
    assert(wildcard_host.has_value());
    assert(moderation_target_matches(
        *wildcard_host, "user", "", "203.0.113.4", std::nullopt,
        "node.example.com"));
    assert(!moderation_target_matches(
        *wildcard_host, "user", "", "203.0.113.4", std::nullopt,
        "example.com"));
    assert(!normalize_ban_target("host", "-bad.example", error).has_value());

    const ModerationEntry active_entry{
        1U,
        ModerationAction::ban,
        *prefix,
        "reason",
        "actor",
        100,
        200,
        0,
        {},
        {}};
    assert(moderation_entry_active(active_entry, 150));
    assert(!moderation_entry_active(active_entry, 200));
    auto permanent_entry = active_entry;
    permanent_entry.expires_at = 0;
    assert(moderation_entry_active(permanent_entry, 1000000));
    permanent_entry.revoked_at = 150;
    assert(!moderation_entry_active(permanent_entry, 151));

    assert(parse_moderation_duration("1s", error) == 1U);
    assert(parse_moderation_duration("1y", error) == 31536000U);
    assert(!parse_moderation_duration("2y", error).has_value());
    assert(!parse_moderation_duration(
        "18446744073709551615y", error).has_value());

    const auto invalid_kick_duration = UserCommandProcessor::parse(
        "!set key.kicks.add=[alice|permanent|reason]", error);
    assert(!invalid_kick_duration.has_value());
    assert(error == "kick duration cannot be permanent");
    assert(!normalize_ban_target(
        "range", "192.0.2.20..192.0.2.10", error).has_value());

    settings.nick_length_minimum = 3;
    settings.nick_length_maximum = 12;
    settings.nick_prefix = "[US],[EU]";
    settings.nick_prefix_nocase = true;
    assert(nickname_allowed("[us]Alice", settings, error));
    assert(!nickname_allowed("Alice", settings, error));
    settings.nick_prefix.clear();
    settings.nick_characters_allowed = "abcdefghijklmnopqrstuvwxyz";
    assert(nickname_allowed("alice", settings, error));
    assert(!nickname_allowed("alice1", settings, error));
    settings.nick_characters_allowed.clear();
    settings.nick_length_maximum = 64;
    assert(!nickname_allowed("alice\tadmin", settings, error));
    assert(!nickname_allowed("alice|admin", settings, error));
    std::string valid_multibyte;
    valid_multibyte.reserve(66U);
    for (std::size_t index = 0; index < 33U; ++index) valid_multibyte += "ą";
    assert(nickname_allowed(valid_multibyte, settings, error));
    assert(valid_moderation_nickname(valid_multibyte));

    const auto invalid_flag = UserCommandProcessor::parse(
        "!set key.user.hide.share.username=[alice.2]", error);
    assert(!invalid_flag.has_value());
    assert(error == "flag must be 0 or 1");

    const auto invalid_duration = UserCommandProcessor::parse(
        "!set key.user.restrict.gag.username.time=[alice.0d]", error);
    assert(!invalid_duration.has_value());
    assert(error == "duration must be 1m..365d using m, h or d");

    const auto invalid_class =
        UserCommandProcessor::parse(
            "!set key.user.new.username.class.password=[alice.6.StrongPass123]",
            error);
    assert(!invalid_class.has_value());
    assert(error == "invalid user class");

    const auto encoded = hash_password("StrongPass.123");
    assert(encoded.starts_with("md5$"));
    assert(encoded.size() == 36U);
    assert(verify_password("StrongPass.123", encoded));
    assert(!verify_password("WrongPass.123", encoded));
    assert(hash_password("password") ==
           "md5$5f4dcc3b5aa765d61d8327deb882cf99");
    const auto pbkdf2 = hash_password(
        "StrongPass.123", PasswordHashAlgorithm::pbkdf2_sha256);
    assert(pbkdf2.starts_with("pbkdf2-sha256$"));
    assert(verify_password("StrongPass.123", pbkdf2));
    assert(!verify_password("WrongPass.123", pbkdf2));
    assert(!verify_password("StrongPass.123", "md5$not-hex"));

    assert(authorize_action(
        UserClass::regular, UserSetAction::self_add_password).allowed);
    assert(authorize_action(
        UserClass::operator_user, UserSetAction::list_bans).allowed);
    assert(authorize_action(
        UserClass::operator_user, UserSetAction::kick_user).allowed);
    assert(authorize_action(
        UserClass::operator_user, UserSetAction::create_user).allowed);
    assert(!authorize_action(
        UserClass::operator_user, UserSetAction::create_ban).allowed);
    assert(authorize_action(
        UserClass::admin, UserSetAction::create_ban).allowed);
    assert(authorize_action(
        UserClass::admin, UserSetAction::change_password_by_id).allowed);
    assert(!authorize_action(
        UserClass::admin, UserSetAction::change_class).allowed);
    assert(authorize_action(
        UserClass::master, UserSetAction::change_class).allowed);
    assert(authorize_action(
        UserClass::master, UserSetAction::set_hub_setting).allowed);
    for (int action = 0;
         action <= static_cast<int>(UserSetAction::list_kicks);
         ++action) {
        assert(permission_for_action(
            static_cast<UserSetAction>(action)).has_value());
    }
    assert(!authorize_action(
        UserClass::master, static_cast<UserSetAction>(999)).allowed);
}

}  // namespace dc24h::tests

int main() {
    dc24h::tests::run_user_command_tests();
    std::cout << "user command tests passed\n";
    return 0;
}
