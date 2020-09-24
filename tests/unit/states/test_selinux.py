"""
    :codeauthor: Jayesh Kariya <jayeshk@saltstack.com>
"""
# Import Python libs

# Import Salt Libs
import salt.states.selinux as selinux

# Import Salt Testing Libs
from tests.support.mixins import LoaderModuleMockMixin
from tests.support.mock import MagicMock, patch
from tests.support.unit import TestCase


class SelinuxTestCase(TestCase, LoaderModuleMockMixin):
    """
    Test cases for salt.states.selinux
    """

    def setup_loader_modules(self):
        return {selinux: {}}

    # 'mode' function tests: 1

    def test_mode(self):
        """
        Test to verifies the mode SELinux is running in,
        can be set to enforcing or permissive.
        """
        ret = {
            "name": "unknown",
            "changes": {},
            "result": False,
            "comment": "unknown is not an accepted mode",
        }
        self.assertDictEqual(selinux.mode("unknown"), ret)

        mock_en = MagicMock(return_value="Enforcing")
        mock_pr = MagicMock(side_effect=["Permissive", "Enforcing"])
        with patch.dict(
            selinux.__salt__,
            {
                "selinux.getenforce": mock_en,
                "selinux.getconfig": mock_en,
                "selinux.setenforce": mock_pr,
            },
        ):
            comt = "SELinux is already in Enforcing mode"
            ret = {"name": "Enforcing", "comment": comt, "result": True, "changes": {}}
            self.assertDictEqual(selinux.mode("Enforcing"), ret)

            with patch.dict(selinux.__opts__, {"test": True}):
                comt = "SELinux mode is set to be changed to Permissive"
                ret = {
                    "name": "Permissive",
                    "comment": comt,
                    "result": None,
                    "changes": {"new": "Permissive", "old": "Enforcing"},
                }
                self.assertDictEqual(selinux.mode("Permissive"), ret)

            with patch.dict(selinux.__opts__, {"test": False}):
                comt = "SELinux has been set to Permissive mode"
                ret = {
                    "name": "Permissive",
                    "comment": comt,
                    "result": True,
                    "changes": {"new": "Permissive", "old": "Enforcing"},
                }
                self.assertDictEqual(selinux.mode("Permissive"), ret)

                comt = "Failed to set SELinux to Permissive mode"
                ret.update(
                    {
                        "name": "Permissive",
                        "comment": comt,
                        "result": False,
                        "changes": {},
                    }
                )
                self.assertDictEqual(selinux.mode("Permissive"), ret)

    # 'boolean' function tests: 1

    def test_boolean(self):
        """
        Test to set up an SELinux boolean.
        """
        name = "samba_create_home_dirs"
        value = True
        ret = {"name": name, "changes": {}, "result": False, "comment": ""}

        mock_en = MagicMock(return_value=[])
        with patch.dict(selinux.__salt__, {"selinux.list_sebool": mock_en}):
            comt = "Boolean {} is not available".format(name)
            ret.update({"comment": comt})
            self.assertDictEqual(selinux.boolean(name, value), ret)

        mock_bools = MagicMock(return_value={name: {"State": "on", "Default": "on"}})
        with patch.dict(selinux.__salt__, {"selinux.list_sebool": mock_bools}):
            comt = "None is not a valid value for the boolean"
            ret.update({"comment": comt})
            self.assertDictEqual(selinux.boolean(name, None), ret)

            comt = "Boolean is in the correct state"
            ret.update({"comment": comt, "result": True})
            self.assertDictEqual(selinux.boolean(name, value, True), ret)

            comt = "Boolean is in the correct state"
            ret.update({"comment": comt, "result": True})
            self.assertDictEqual(selinux.boolean(name, value), ret)

        mock_bools = MagicMock(return_value={name: {"State": "off", "Default": "on"}})
        mock = MagicMock(side_effect=[True, False])
        with patch.dict(
            selinux.__salt__,
            {"selinux.list_sebool": mock_bools, "selinux.setsebool": mock},
        ):
            with patch.dict(selinux.__opts__, {"test": True}):
                comt = "Boolean samba_create_home_dirs" " is set to be changed to on"
                ret.update({"comment": comt, "result": None})
                self.assertDictEqual(selinux.boolean(name, value), ret)

            with patch.dict(selinux.__opts__, {"test": False}):
                comt = "Boolean samba_create_home_dirs has been set to on"
                ret.update({"comment": comt, "result": True})
                ret.update({"changes": {"State": {"old": "off", "new": "on"}}})
                self.assertDictEqual(selinux.boolean(name, value), ret)

                comt = "Failed to set the boolean " "samba_create_home_dirs to on"
                ret.update({"comment": comt, "result": False})
                ret.update({"changes": {}})
                self.assertDictEqual(selinux.boolean(name, value), ret)

    # 'port_policy_present' function tests: 1

    def test_port_policy_present(self):
        """
        Test to set up an SELinux port.
        """
        name = "tcp/8080"
        protocol = "tcp"
        port = "8080"
        ret = {"name": name, "changes": {}, "result": False, "comment": ""}

        mock_add = MagicMock(return_value={"retcode": 0})
        mock_modify = MagicMock(return_value={"retcode": 0})
        mock_get = MagicMock(
            return_value={
                "sel_type": "http_cache_port_t",
                "protocol": "tcp",
                "port": "8080",
            }
        )
        with patch.dict(
            selinux.__salt__,
            {
                "selinux.port_get_policy": mock_get,
                "selinux.port_add_policy": mock_add,
                "selinux.port_modify_policy": mock_modify,
            },
        ):
            comt = 'SELinux policy for "{}" already present '.format(name)
            ret.update({"comment": comt, "result": True})
            self.assertDictEqual(
                selinux.port_policy_present(name, "http_cache_port_t"), ret
            )

            with patch.dict(selinux.__opts__, {"test": True}):
                ret.update({"comment": "", "result": None})
                self.assertDictEqual(
                    selinux.port_policy_present(name, "http_port_t"), ret
                )

            with patch.dict(selinux.__opts__, {"test": False}):
                ret.update(
                    {
                        "comment": "",
                        "changes": {
                            "old": {
                                "sel_type": "http_cache_port_t",
                                "protocol": "tcp",
                                "port": "8080",
                            },
                            "new": {
                                "sel_type": "http_port_t",
                                "protocol": "tcp",
                                "port": "8080",
                            },
                        },
                        "result": True,
                    }
                )
                self.assertDictEqual(
                    selinux.port_policy_present(name, "http_port_t"), ret
                )

        mock_add = MagicMock(return_value={"retcode": 0})
        mock_modify = MagicMock(return_value={"retcode": 0})
        mock_get = MagicMock(return_value=None)
        with patch.dict(
            selinux.__salt__,
            {
                "selinux.port_get_policy": mock_get,
                "selinux.port_add_policy": mock_add,
                "selinux.port_modify_policy": mock_modify,
            },
        ):
            with patch.dict(selinux.__opts__, {"test": True}):
                ret.update({"comment": "", "result": None})
                self.assertDictEqual(
                    selinux.port_policy_present(name, "http_cache_port_t"), ret
                )

            with patch.dict(selinux.__opts__, {"test": False}):
                ret.update(
                    {
                        "comment": "",
                        "changes": {
                            "old": None,
                            "new": {
                                "sel_type": "http_cache_port_t",
                                "protocol": "tcp",
                                "port": "8080",
                            },
                        },
                        "result": True,
                    }
                )
                self.assertDictEqual(
                    selinux.port_policy_present(name, "http_cache_port_t"), ret
                )

            with patch.dict(selinux.__opts__, {"test": False}):
                ret.update(
                    {
                        "comment": "",
                        "changes": {
                            "old": None,
                            "new": {
                                "sel_type": "http_cache_port_t",
                                "protocol": "tcp",
                                "port": "8081",
                            },
                        },
                        "result": True,
                    }
                )
                self.assertDictEqual(
                    selinux.port_policy_present(
                        "required_protocol_port",
                        "http_cache_port_t",
                        protocol="tcp",
                        port="8081",
                    ),
                    ret,
                )

        mock_add = MagicMock(return_value={"retcode": 1})
        mock_modify = MagicMock(return_value={"retcode": 1})
        mock_get = MagicMock(return_value=None)
        with patch.dict(
            selinux.__salt__,
            {
                "selinux.port_get_policy": mock_get,
                "selinux.port_add_policy": mock_add,
                "selinux.port_modify_policy": mock_modify,
            },
        ):
            comt = "Error adding new policy: 1"
            ret.update({"comment": comt, "result": True})
            self.assertDictEqual(
                selinux.port_policy_present(name, "http_cache_port_t"), ret
            )

    # 'port_policy_absent' function tests: 1

    def test_port_policy_absent(self):
        """
        Test to delete an SELinux port.
        """
        name = "tcp/8080"
        protocol = "tcp"
        port = "8080"
        ret = {"name": name, "changes": {}, "result": False, "comment": ""}

        mock_delete = MagicMock(return_value={"retcode": 0})
        mock_get = MagicMock(
            return_value={
                "sel_type": "http_cache_port_t",
                "protocol": "tcp",
                "port": "8080",
            }
        )
        with patch.dict(
            selinux.__salt__,
            {
                "selinux.port_get_policy": mock_get,
                "selinux.port_delete_policy": mock_delete,
            },
        ):
            with patch.dict(selinux.__opts__, {"test": True}):
                ret.update({"comment": "", "result": None})
                self.assertDictEqual(
                    selinux.port_policy_absent(name, "http_cache_port_t"), ret
                )

            with patch.dict(selinux.__opts__, {"test": False}):
                ret.update(
                    {
                        "comment": "",
                        "changes": {
                            "old": {
                                "sel_type": "http_cache_port_t",
                                "protocol": "tcp",
                                "port": "8080",
                            },
                            "new": None,
                        },
                        "result": True,
                    }
                )
                self.assertDictEqual(
                    selinux.port_policy_absent(name, "http_cache_port_t"), ret
                )

        mock_delete = MagicMock(return_value={"retcode": 0})
        mock_get = MagicMock(
            return_value={
                "sel_type": "http_cache_port_t",
                "protocol": "tcp",
                "port": "8081",
            }
        )
        with patch.dict(
            selinux.__salt__,
            {
                "selinux.port_get_policy": mock_get,
                "selinux.port_delete_policy": mock_delete,
            },
        ):
            with patch.dict(selinux.__opts__, {"test": False}):
                ret.update(
                    {
                        "comment": "",
                        "changes": {
                            "old": {
                                "sel_type": "http_cache_port_t",
                                "protocol": "tcp",
                                "port": "8081",
                            },
                            "new": None,
                        },
                        "result": True,
                    }
                )
                self.assertDictEqual(
                    selinux.port_policy_absent(
                        "required_protocol_port",
                        "http_cache_port_t",
                        protocol="tcp",
                        port="8081",
                    ),
                    ret,
                )

        mock_delete = MagicMock(return_value={"retcode": 2})
        mock_get = MagicMock(
            return_value={
                "sel_type": "http_cache_port_t",
                "protocol": "tcp",
                "port": "8080",
            }
        )
        with patch.dict(
            selinux.__salt__,
            {
                "selinux.port_get_policy": mock_get,
                "selinux.port_delete_policy": mock_delete,
            },
        ):
            comt = "Error deleting policy: 2"
            ret.update({"comment": comt, "result": True})
            self.assertDictEqual(
                selinux.port_policy_absent(name, "http_cache_port_t"), ret
            )

        mock_delete = MagicMock(return_value={"retcode": 0})
        mock_get = MagicMock(return_value=None)
        with patch.dict(
            selinux.__salt__,
            {
                "selinux.port_get_policy": mock_get,
                "selinux.port_delete_policy": mock_delete,
            },
        ):
            comt = 'SELinux policy for "{}" already absent '.format(name)
            ret.update({"comment": comt, "result": True})
            self.assertDictEqual(
                selinux.port_policy_absent(name, "http_cache_port_t"), ret
            )
