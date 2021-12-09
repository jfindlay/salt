"""
Audit logging for salt
"""

import hashlib
import hmac
import logging
import socket
import uuid

import salt._logging
import salt.payload
import salt.utils.stringutils

# Cache hostname lookup; cannot use `platform.node()` for this because of
# module namespace collision within salt package
hostname = socket.gethostname()
del socket

log = logging.getLogger(__name__)
audit_log = salt._logging.get_audit_logger()


class Audit:
    """
    Audit logger
    """

    def __init__(self, opts):
        """
        Setup audit logger
        """
        self.opts = opts
        self.filtered_message = "<filtered from audit log>"
        self.hashed_prefix = "<hashed>"

    def _hash_value(self, field_value):
        """
        HMAC hash a field value in the load
        """
        field_str = field_value if isinstance(field_value, str) else str(field_value)
        return (
            self.hashed_prefix
            + hmac.new(
                salt.utils.stringutils.to_bytes(self.opts["audit_log_hmac_key"]),
                field_str.encode(__salt_system_encoding__),
                hashlib.sha256,
            ).hexdigest()
        )

    def _filter_req(self, load):
        """
        Filter or otherwise transform fields in the request load before sending
        the request to the audit log
        """
        for cmd_pat in (load["cmd"], "*"):
            if cmd_pat in self.opts["audit_log_exclude_req_fields"]:
                for field in self.opts["audit_log_exclude_req_fields"][cmd_pat]:
                    if field in load:
                        load[field] = self.filtered_message

            if cmd_pat in self.opts["audit_log_hash_req_fields"]:
                for field_pat in self.opts["audit_log_hash_req_fields"][cmd_pat]:
                    if field_pat == "*":
                        load = {
                            f: load[f]
                            # Exempt the RPC function name from hashing
                            if f == "cmd" else self._hash_value(load[f])
                            for f in load
                        }
                        break
                    elif field_pat in load:
                        load[field_pat] = self._hash_value(load[field_pat])
        return load

    def _filter_ret(self, ret_data, req_opts):
        """
        Filter or otherwise transform fields in the return before sending it to
        the audit log.

        The payload of the ``return`` contains two parts: the data the caller
        requested and some metadata called ``req_opts``.
        """
        # Remove or hash the entire return data if the metadata `key` is in the
        # user's exclude or hash lists
        if req_opts.get("key"):
            if req_opts["key"] in self.opts["audit_log_exclude_ret_data"]:
                ret_data = self.filtered_message
            elif req_opts["key"] in self.opts["audit_log_hash_ret_data"]:
                ret_data = self._hash_value(ret_data)
        # Otherwise, selectively filter fields from the returned data
        elif isinstance(ret_data, dict):
            ret_data = {
                k: self.filtered_message
                if k in self.opts["audit_log_exclude_ret_fields"]
                else v
                for k, v in ret_data.items()
            }
        return (ret_data, req_opts)

    def audit_req(self, payload):
        """
        Send incoming payloads to the audit log
        """
        audit_id = uuid.uuid4().hex
        try:
            # Copy request payload
            payload_copy = salt.payload.loads(salt.payload.dumps(payload))
            if (
                payload_copy["load"].get("cmd", "")
                not in self.opts["audit_log_exclude_cmds"]
            ):
                payload_copy["load"] = self._filter_req(payload_copy["load"])
                audit_log.info(
                    {
                        "request": payload_copy,
                        "master": self.opts.get("id"),
                        "host": hostname,
                        "audit_id": audit_id,
                    }
                )

                # Return unique hash to be used to correlate return log with
                # request log
                return audit_id
        except Exception as ex:
            try:
                audit_log.error(
                    {
                        "request": "Cannot log request: {}".format(ex),
                        "master": self.opts.get("id"),
                        "host": hostname,
                        "audit_id": audit_id,
                    }
                )
            except Exception as ex_ex:
                log.error("Cannot audit log payload for {}: {}".format(audit_id, ex_ex))

    def audit_ret(self, ret, audit_id):
        """
        Send outgoing return data to the audit log

        Filtering the response data is more challenging because the response
        data, which although may have a type convention, originates from
        calling whatever ``cmd`` the user requested.  In addition, many of the
        ``AESFuncs`` and ``ClearFuncs`` called return the results of other
        functions.  The advice is that we need to do the python thing and be
        apprehensive about each return's structure.
        """
        try:
            if isinstance(ret, (tuple, list)):
                if len(ret) == 2 and isinstance(ret[1], dict):
                    # Copy return data
                    ret_data, req_opts = salt.payload.loads(salt.payload.dumps(ret))
                    new_ret = self._filter_ret(ret_data, req_opts)
                    audit_log.info(
                        {
                            "return": new_ret,
                            "master": self.opts.get("id"),
                            "host": hostname,
                            "audit_id": audit_id,
                        }
                    )
                    return
            audit_log.warning(
                {
                    "return": "Unknown return format detected: excluding return data from log",
                    "master": self.opts.get("id"),
                    "host": hostname,
                    "audit_id": audit_id,
                }
            )
            audit_log.info(
                {
                    "return": self.filtered_message,
                    "master": self.opts.get("id"),
                    "host": hostname,
                    "audit_id": audit_id,
                }
            )

        except Exception as ex:
            try:
                audit_log.error(
                    {
                        "return": "Cannot log return: {}".format(ex),
                        "master": self.opts.get("id"),
                        "host": hostname,
                        "audit_id": audit_id,
                    }
                )
            except Exception as ex_ex:
                log.error(
                    "Cannot audit log return payload for {}: {}".format(audit_id, ex_ex)
                )
