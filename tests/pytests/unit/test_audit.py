"""
Tests for salt.audit
"""
import copy
import secrets
import string
import uuid

import pytest

import salt.audit
import salt.utils.stringutils
from tests.support.mock import MagicMock, patch


def audit_config():
    """
    Salt config for audit logging.
    """
    return {
        "audit_log": True,
        "audit_log_hmac_key": secrets.token_urlsafe(64),
        "audit_log_exclude_cmds": ["_minion_event"],
        "audit_log_exclude_req_fields": {"_pillar": ["grains"], "_return": ["return"]},
        "audit_log_exclude_ret_data": ["pillar"],
        "audit_log_exclude_ret_fields": ["tok", "hsum"],
        "audit_log_hash_req_fields": {
            "*": ["key", "tok"],
            "_pillar": ["*"],
            "_return": ["id"],
        },
        "audit_log_hash_ret_data": ["pillar"],
    }


@pytest.fixture
def events():
    """
    Sample request and return salt event pairs.
    """
    return {
        "pillar": {
            "request": {
                "enc": "aes",
                "load": {
                    "cmd": "_pillar",
                    "extra_minion_data": {},
                    "grains": {
                        "os": "Debian",
                        "os_family": "Debian",
                        "osarch": "amd64",
                        "oscodename": "bookworm",
                        "osfinger": "Debian-12",
                        "osfullname": "Debian GNU/Linux",
                        "osmajorrelease": 12,
                        "osrelease": "12",
                        "osrelease_info": [12],
                    },
                    "id": "bob",
                    "pillar_override": {},
                    "pillarenv": "None",
                    "saltenv": "None",
                    "ver": "2",
                },
                "version": 2,
            },
            "return": (
                {"some": "data"},
                {"fun": "send_private", "key": "pillar", "tgt": "bob"},
            ),
        },
        "minion_event": {
            "request": {
                "enc": "aes",
                "load": {
                    "id": "bob",
                    "cmd": "_minion_event",
                    "pretag": None,
                    "tok": b"O\x80S\xe8\x87\x9a}wE\x85\x8a\x0eX`\xbe\x06E\x87\xb4\x1fxw\xfe\x9dw\xdc\x0cl\x95\xe71x\x88\xf1\x16>\n\xb4\xa2\x89*\xdc\xeaVa\x1a\x85\x0e\x172p\x9bFxQ\xc7\xbd~\xb5\xef2C\xef\x9d\xa9\x02}\x8e+\xdd\x1f+45\xb6\x94&D\xab\xd0\xa2\n\x15\\\x97\x00a\xf1\xbec\xd3\xd2\x86)\x7f\x19/\xd6{\xdbD>\xdc\x84\xc9\x1bg\x1b\xea=\xd6\xde\xaa\x10\x0e\x90\x00hC\xed\x7fO4}eS]\xd2\xa5]\xef9\r\x8b\xa0\x9d:\x7fS\x93Y\xc5\xcdW-\xc0\xaf\xc7\xd0\\\xe1VH\xb2\x82\x984\x91\xa3\xe8v\xbeN\x97z\xc4B\xf7\x84]\xb7y\x0f!0*\x05\xf3\xb5\xb3\xb0C2\xfd\x03\xd2\x94,i|x\xc6\xf0\xc51\xe5fP\xd0\xac\x12\x1d\x1c\xc3\xe4\x8f\x11m\xc3\xd9\xdd\xa1e\x98Q\x86\x18\xd6\x1c\xbe\x1b\xfd\xa3Q\x0f\xee\xd8d\x1e\x14e\xee\xe4\xecs\xe0B\xc7\x07\x18\xc5\x7fn\xc0\x94\xed\xed\xf0Ix\x1f\xbaw\xd8oy",
                    "data": "Minion bob started at Mon Oct 16 23:36:14 2023",
                    "tag": "minion_start",
                },
                "version": 2,
            },
            "return": None,
        },
        "test.ping": {
            "request": {
                "enc": "clear",
                "load": {
                    "cmd": "publish",
                    "tgt": "*",
                    "fun": "test.ping",
                    "arg": [],
                    "key": "Zenzcfey+JQ7N58Zb/psPbfsw+9asCYXx0GJvzPVyJMsm3wZZl102TTlB8knWmMIjrlavWjqnVk=",
                    "tgt_type": "glob",
                    "ret": "",
                    "jid": "",
                    "kwargs": {
                        "show_timeout": True,
                        "show_jid": False,
                        "delimiter": ":",
                    },
                    "user": "root",
                },
                "version": 2,
            },
            "return": (
                {
                    "enc": "clear",
                    "load": {
                        "jid": "20231016233615429177",
                        "minions": ["bob"],
                        "missing": [],
                    },
                },
                {"fun": "send_clear"},
            ),
        },
        "_return": {
            "request": {
                "enc": "aes",
                "load": {
                    "cmd": "_return",
                    "id": "bob",
                    "success": True,
                    "return": True,
                    "retcode": 0,
                    "jid": "20231016233615429177",
                    "fun": "test.ping",
                    "fun_args": [],
                    "user": "root",
                },
                "version": 2,
            },
            "return": (None, {"fun": "send"}),
        },
        "_file_hash": {
            "request": {
                "enc": "aes",
                "load": {"path": "test.sls", "saltenv": "base", "cmd": "_file_hash"},
                "version": 2,
            },
            "return": (
                {
                    "hash_type": "sha256",
                    "hsum": "b09256f3610613a592aa980b16bbdce35de5d974d683dbedd832b32e7dee9b6c",
                },
                {"fun": "send"},
            ),
        },
    }


@pytest.fixture
def audit():
    """
    Audit log instance.
    """
    return salt.audit.Audit(audit_config())


def test__hash_value(audit):
    """
    Test hashing data in the audit log.
    """
    simple_hashed = audit._hash_value("toomanysecrets")
    assert isinstance(simple_hashed, str)
    assert simple_hashed.startswith(audit.hashed_prefix)

    object_hashed = audit._hash_value(
        {"sneakers": {"theme": "toomanysecrets", "action": "some"}}
    )
    assert isinstance(object_hashed, str)
    assert object_hashed.startswith(audit.hashed_prefix)


def test__filter_req(audit, events):
    """
    Test filtering request.
    """
    filtered_pillar_load = audit._filter_req(
        copy.deepcopy(events["pillar"]["request"]["load"])
    )
    for key in filtered_pillar_load:
        if key == "cmd":
            assert filtered_pillar_load[key] == "_pillar"
        else:
            assert filtered_pillar_load[key].startswith(audit.hashed_prefix)

    filtered_minion_event_load = audit._filter_req(
        copy.deepcopy(events["minion_event"]["request"]["load"])
    )
    for key in filtered_minion_event_load:
        if key in ["key", "tok"]:
            assert filtered_minion_event_load[key].startswith(audit.hashed_prefix)
        else:
            assert (
                filtered_minion_event_load[key]
                == events["minion_event"]["request"]["load"][key]
            )

    filtered_test_ping_load = audit._filter_req(
        copy.deepcopy(events["test.ping"]["request"]["load"])
    )
    for key in filtered_test_ping_load:
        if key in ["key"]:
            assert filtered_test_ping_load[key].startswith(audit.hashed_prefix)
        else:
            assert (
                filtered_test_ping_load[key]
                == events["test.ping"]["request"]["load"][key]
            )

    filtered__return_load = audit._filter_req(
        copy.deepcopy(events["_return"]["request"]["load"])
    )
    for key in filtered__return_load:
        if key in ["id"]:
            assert filtered__return_load[key].startswith(audit.hashed_prefix)
        elif key in ["return"]:
            assert filtered__return_load[key] == audit.filtered_message
        else:
            assert (
                filtered__return_load[key] == events["_return"]["request"]["load"][key]
            )

    filtered__file_hash_load = audit._filter_req(
        copy.deepcopy(events["_file_hash"]["request"]["load"])
    )
    assert filtered__file_hash_load == events["_file_hash"]["request"]["load"]


def test__filter_ret(audit, events):
    """
    Test filtering return.
    """
    filtered_pillar_ret_data, filtered_pillar_req_opts = audit._filter_ret(
        *copy.deepcopy(events["pillar"]["return"])
    )
    assert filtered_pillar_ret_data == audit.filtered_message
    assert filtered_pillar_req_opts == events["pillar"]["return"][1]

    # No minion_event return

    filtered_test_ping_ret_data, filtered_test_ping_req_opts = audit._filter_ret(
        *copy.deepcopy(events["test.ping"]["return"])
    )
    assert filtered_test_ping_ret_data == events["test.ping"]["return"][0]
    assert filtered_test_ping_req_opts == events["test.ping"]["return"][1]

    filtered__return_ret_data, filtered__return_req_opts = audit._filter_ret(
        *copy.deepcopy(events["_return"]["return"])
    )
    assert filtered__return_ret_data == events["_return"]["return"][0]
    assert filtered__return_req_opts == events["_return"]["return"][1]

    filtered__file_hash_ret_data, filtered__file_hash_req_opts = audit._filter_ret(
        *copy.deepcopy(events["_file_hash"]["return"])
    )
    for key in filtered__file_hash_ret_data:
        if key == "hsum":
            assert filtered__file_hash_ret_data[key] == audit.filtered_message
        else:
            assert (
                filtered__file_hash_ret_data[key]
                == events["_file_hash"]["return"][0][key]
            )
    assert filtered__file_hash_req_opts == events["_file_hash"]["return"][1]


def test_audit_req(audit, events):
    """
    Test auditing request.
    """
    # Normal case should just return the `audit_id`
    with patch("salt.audit.audit_log"), patch(
        "salt.audit.audit_log.info"
    ) as audit_info, patch("salt.audit.audit_log.error") as audit_error:
        audit_id = audit.audit_req(copy.deepcopy(events["pillar"]["request"]))
        # It's an unpunctuated UUID str
        assert isinstance(audit_id, str)
        assert len(audit_id) == 8 + 4 + 4 + 4 + 12
        assert [c in string.hexdigits for c in audit_id]
        # Test actual audit log record happened
        audit_info.assert_called_once()
        audit_error.assert_not_called()

    # First exception logs to audit logger
    with patch("salt.audit.audit_log"), patch(
        "salt.audit.audit_log.info", MagicMock(side_effect=Exception)
    ), patch("salt.audit.audit_log.error") as audit_error:
        audit.audit_req(copy.deepcopy(events["pillar"]["request"]))
        audit_error.assert_called_once()

    # Second exception logs to general logger
    with patch("salt.audit.audit_log"), patch(
        "salt.audit.audit_log.info", MagicMock(side_effect=Exception)
    ), patch("salt.audit.audit_log.error", MagicMock(side_effect=Exception)), patch(
        "salt.audit.log"
    ), patch(
        "salt.audit.log.error"
    ) as log_error:
        audit.audit_req(copy.deepcopy(events["pillar"]["request"]))
        log_error.assert_called_once()


def test_audit_ret(audit, events):
    """
    Test auditing return.
    """
    # Normal case should just return the `audit_id`
    with patch("salt.audit.audit_log"), patch(
        "salt.audit.audit_log.info"
    ) as audit_info, patch("salt.audit.audit_log.error") as audit_error:
        audit.audit_ret(copy.deepcopy(events["pillar"]["return"]), uuid.uuid4().hex)
        # Test actual audit log record happened
        audit_info.assert_called_once()
        audit_error.assert_not_called()

    # Unknown return format
    with patch("salt.audit.audit_log"), patch(
        "salt.audit.audit_log.info"
    ) as audit_info, patch("salt.audit.audit_log.warning") as audit_warning:
        audit.audit_ret(None, uuid.uuid4().hex)
        audit_warning.assert_called_once()
        audit_info.assert_called_once()

    # First exception logs to audit logger
    with patch("salt.audit.audit_log"), patch(
        "salt.audit.audit_log.info", MagicMock(side_effect=Exception)
    ), patch("salt.audit.audit_log.error") as audit_error:
        audit.audit_ret(copy.deepcopy(events["pillar"]["return"]), uuid.uuid4().hex)
        audit_error.assert_called_once()

    # Second exception logs to general logger
    with patch("salt.audit.audit_log"), patch(
        "salt.audit.audit_log.info", MagicMock(side_effect=Exception)
    ), patch("salt.audit.audit_log.error", MagicMock(side_effect=Exception)), patch(
        "salt.audit.log"
    ), patch(
        "salt.audit.log.error"
    ) as log_error:
        audit.audit_ret(copy.deepcopy(events["pillar"]["return"]), uuid.uuid4().hex)
        log_error.assert_called_once()
