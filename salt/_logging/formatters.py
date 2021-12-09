"""
    salt._logging.formatters
    ~~~~~~~~~~~~~~~~~~~~~~

    Salt's logging formatters
"""
import json
import logging


class AuditFormatter(logging.Formatter):
    """
    Format audit log records in JSON
    """

    @staticmethod
    def _decode_bytes(o):
        """
        Helper method for `json` package.  Decode bytes to representative
        string characters in the prevailing encoding.

        https://docs.python.org/3/library/json.html#json.JSONEncoder.default
        https://docs.python.org/3/library/codecs.html#error-handlers
        """
        if isinstance(o, bytes):
            return o.decode(__salt_system_encoding__, "backslashreplace")
        # Not going to do anything with an object type we don't know how to
        # serialize
        raise TypeError(
            "Cannot JSON serialize object of type {}".format(o.__class__.__name__)
        )

    def format(self, record):
        """
        Format an audit log record in JSON
        """
        return json.dumps(
            {
                "date": super(AuditFormatter, self).formatTime(record),
                "level": record.levelname,
                "message": record.msg,
            },
            default=AuditFormatter._decode_bytes,
        )

    def formatException(self, exc_info):
        """
        Format an exception for the audit log
        """
        return json.dumps(
            {
                "date": super(AuditFormatter, self).formatTime(record),
                "level": record.levelname,
                "exception": super(AuditFormatter, self).formatException(exc_info),
            },
            default=AuditFormatter._decode_bytes,
        )

    def formatStack(self, stack_info):
        """
        Format stack information for the audit log
        """
        return json.dumps(
            {
                "date": super(AuditFormatter, self).formatTime(record),
                "level": record.levelname,
                "stack": super(AuditFormatter, self).formatStack(stack_info),
            },
            default=AuditFormatter._decode_bytes,
        )
