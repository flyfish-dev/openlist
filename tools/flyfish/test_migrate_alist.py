import unittest

from migrate_alist import convert_user


class RoleMigrationTests(unittest.TestCase):
    def test_legacy_scalar_role_is_unchanged(self):
        self.assertEqual(convert_user({"role": 1, "base_path": "/private", "permission": 0}, {})["base_path"], "/private")

    def test_admin_keeps_admin(self):
        self.assertEqual(convert_user({"role": "[2]"}, {2: {"name": "admin"}})["role"], 2)

    def test_guest_path_is_not_broadened(self):
        roles = {1: {"name": "guest", "raw_permission": ""},
                 5: {"name": "scoped", "raw_permission": '[{"path":"/private","permission":0}]'}}
        result = convert_user({"role": "[1,5]", "base_path": "/"}, roles)
        self.assertEqual((result["role"], result["base_path"], result["permission"]), (1, "/private", 0))

    def test_nonrepresentable_scopes_fail_closed(self):
        roles = {3: {"name": "custom", "raw_permission": '[{"path":"/a","permission":0},{"path":"/b","permission":8}]'}}
        with self.assertRaises(ValueError):
            convert_user({"role": "[3]"}, roles)

    def test_disjoint_base_and_scope_fail_closed(self):
        roles = {3: {"name": "custom", "raw_permission": '[{"path":"/a","permission":0}]'}}
        with self.assertRaises(ValueError):
            convert_user({"role": "[3]", "base_path": "/b"}, roles)


if __name__ == "__main__":
    unittest.main()
