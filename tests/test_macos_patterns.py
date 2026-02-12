#!/usr/bin/env python3
"""
Tests for macOS-specific dangerous and safe patterns.
Added in v1.3.6.
"""

import unittest
import sys
from pathlib import Path

# Add hooks directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "hooks"))

from pre_tool_use import check_dangerous, check_safe
from pre_read import check_dangerous_patterns as check_dangerous_read


class TestMacOSDangerousPatterns(unittest.TestCase):
    """Test macOS-specific dangerous command patterns."""

    # === DISK UTILITY ===

    def test_diskutil_erase_disk(self):
        dangerous, pattern_data = check_dangerous("diskutil eraseDisk JHFS+ NewDisk disk2")
        self.assertTrue(dangerous)
        self.assertIsNotNone(pattern_data)
        self.assertIn("disk", pattern_data['message'].lower())

    def test_diskutil_erase_volume(self):
        dangerous, msg = check_dangerous("diskutil eraseVolume JHFS+ NewVolume disk2s1")
        self.assertTrue(dangerous)

    def test_diskutil_partition(self):
        dangerous, msg = check_dangerous("diskutil partitionDisk disk2 GPT JHFS+ NewPart 100%")
        self.assertTrue(dangerous)

    def test_diskutil_apfs_delete(self):
        dangerous, msg = check_dangerous("diskutil apfs deleteContainer disk2")
        self.assertTrue(dangerous)

    def test_diskutil_secure_erase(self):
        dangerous, msg = check_dangerous("diskutil secureErase 0 disk2")
        self.assertTrue(dangerous)

    def test_diskutil_zero_disk(self):
        dangerous, msg = check_dangerous("diskutil zeroDisk disk2")
        self.assertTrue(dangerous)

    # === KEYCHAIN ACCESS ===

    def test_security_delete_keychain(self):
        dangerous, pattern_data = check_dangerous("security delete-keychain login.keychain")
        self.assertTrue(dangerous)
        self.assertIsNotNone(pattern_data)
        self.assertIn("keychain", pattern_data['message'].lower())

    def test_security_dump_keychain(self):
        dangerous, pattern_data = check_dangerous("security dump-keychain -d login.keychain")
        self.assertTrue(dangerous)
        self.assertIsNotNone(pattern_data)
        self.assertIn("keychain", pattern_data['message'].lower())

    def test_security_find_generic_password(self):
        dangerous, msg = check_dangerous("security find-generic-password -w -s 'MyService'")
        self.assertTrue(dangerous)

    def test_security_find_internet_password(self):
        dangerous, msg = check_dangerous("security find-internet-password -w -s 'example.com'")
        self.assertTrue(dangerous)

    def test_security_export_keychain(self):
        dangerous, msg = check_dangerous("security export -k login.keychain -o exported.pem")
        self.assertTrue(dangerous)

    # === TIME MACHINE ===

    def test_tmutil_delete(self):
        dangerous, msg = check_dangerous("tmutil delete /Volumes/Backup/Backups.backupdb/Mac")
        self.assertTrue(dangerous)

    def test_tmutil_disable(self):
        dangerous, msg = check_dangerous("tmutil disable")
        self.assertTrue(dangerous)

    def test_tmutil_deletelocalsnapshots(self):
        dangerous, msg = check_dangerous("tmutil deletelocalsnapshots /")
        self.assertTrue(dangerous)

    def test_rm_backups_backupdb(self):
        dangerous, msg = check_dangerous("rm -rf /Volumes/Backup/Backups.backupdb")
        self.assertTrue(dangerous)

    # === DIRECTORY SERVICES ===

    def test_dscl_delete_user(self):
        dangerous, msg = check_dangerous("dscl . -delete /Users/testuser")
        self.assertTrue(dangerous)

    def test_dscl_delete_group(self):
        dangerous, msg = check_dangerous("dscl . -delete /Groups/testgroup")
        self.assertTrue(dangerous)

    def test_dscl_append_admin(self):
        dangerous, msg = check_dangerous("dscl . -append /Groups/admin GroupMembership testuser")
        self.assertTrue(dangerous)

    # === SYSTEM SECURITY ===

    def test_spctl_disable(self):
        dangerous, pattern_data = check_dangerous("spctl --master-disable")
        self.assertTrue(dangerous)
        self.assertIsNotNone(pattern_data)
        self.assertIn("gatekeeper", pattern_data['message'].lower())

    def test_csrutil_disable(self):
        dangerous, msg = check_dangerous("csrutil disable")
        self.assertTrue(dangerous)

    def test_systemsetup_enable_ssh(self):
        dangerous, msg = check_dangerous("systemsetup -setremotelogin on")
        self.assertTrue(dangerous)

    def test_nvram_boot_args(self):
        dangerous, msg = check_dangerous("nvram boot-args='-v'")
        self.assertTrue(dangerous)

    # === PRIVACY DATABASE ===

    def test_tcc_database_sqlite(self):
        dangerous, msg = check_dangerous("sqlite3 ~/Library/Application\\ Support/com.apple.TCC/TCC.db")
        self.assertTrue(dangerous)

    def test_tccutil_reset(self):
        dangerous, msg = check_dangerous("tccutil reset All")
        self.assertTrue(dangerous)

    # === PERSISTENCE ===

    def test_launchctl_load_daemon(self):
        dangerous, pattern_data = check_dangerous("launchctl load /Library/LaunchDaemons/evil.plist")
        self.assertTrue(dangerous)
        self.assertIsNotNone(pattern_data)
        self.assertIn("persistence", pattern_data['message'].lower())

    def test_launchctl_unload_apple(self):
        dangerous, msg = check_dangerous("launchctl unload /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist")
        self.assertTrue(dangerous)

    def test_cp_plist_to_launchdaemons(self):
        dangerous, msg = check_dangerous("cp evil.plist /Library/LaunchDaemons/")
        self.assertTrue(dangerous)

    def test_cp_plist_to_launchagents(self):
        dangerous, msg = check_dangerous("cp evil.plist ~/Library/LaunchAgents/")
        self.assertTrue(dangerous)

    def test_mv_plist_to_launch(self):
        dangerous, msg = check_dangerous("mv evil.plist /Library/LaunchDaemons/")
        self.assertTrue(dangerous)


class TestMacOSSafePatterns(unittest.TestCase):
    """Test macOS-specific safe command patterns."""

    def test_diskutil_list(self):
        self.assertTrue(check_safe("diskutil list"))

    def test_diskutil_info(self):
        self.assertTrue(check_safe("diskutil info disk2"))

    def test_system_profiler(self):
        self.assertTrue(check_safe("system_profiler SPHardwareDataType"))

    def test_sw_vers(self):
        self.assertTrue(check_safe("sw_vers"))

    def test_defaults_read(self):
        self.assertTrue(check_safe("defaults read com.apple.finder"))

    def test_security_find_certificate(self):
        self.assertTrue(check_safe("security find-certificate -a"))

    def test_tmutil_listbackups(self):
        self.assertTrue(check_safe("tmutil listbackups"))

    def test_tmutil_status(self):
        self.assertTrue(check_safe("tmutil status"))

    def test_launchctl_list(self):
        self.assertTrue(check_safe("launchctl list"))

    def test_dscl_read(self):
        self.assertTrue(check_safe("dscl . -read /Users/testuser"))

    def test_spctl_status(self):
        self.assertTrue(check_safe("spctl --status"))


class TestMacOSReadPatterns(unittest.TestCase):
    """Test macOS-specific dangerous read patterns."""

    def test_keychain_file(self):
        dangerous, pattern_data = check_dangerous_read("/Users/test/Library/Keychains/login.keychain-db")
        self.assertTrue(dangerous)
        self.assertIsNotNone(pattern_data)
        self.assertIn("keychain", pattern_data['message'].lower())

    def test_tcc_database(self):
        dangerous, msg = check_dangerous_read("/Users/test/Library/Application Support/com.apple.TCC/TCC.db")
        self.assertTrue(dangerous)

    def test_chrome_login_data(self):
        dangerous, msg = check_dangerous_read("/Users/test/Library/Application Support/Google/Chrome/Default/Login Data")
        self.assertTrue(dangerous)

    def test_firefox_logins(self):
        dangerous, msg = check_dangerous_read("/Users/test/Library/Application Support/Firefox/Profiles/abc123.default/logins.json")
        self.assertTrue(dangerous)

    def test_authorization_db(self):
        dangerous, msg = check_dangerous_read("/etc/authorization")
        self.assertTrue(dangerous)

    def test_dslocal_database(self):
        dangerous, msg = check_dangerous_read("/var/db/dslocal/nodes/Default/users/root.plist")
        self.assertTrue(dangerous)


if __name__ == "__main__":
    unittest.main()
