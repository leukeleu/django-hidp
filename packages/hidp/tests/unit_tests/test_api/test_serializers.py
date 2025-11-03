from django.contrib.sessions.backends.db import SessionStore
from django.test import TestCase

from hidp.api.serializers import SessionSerializer


class TestSessionSerializer(TestCase):
    def make_session(self, session_key, data=None):
        # the session key must be longer than 7 characters long to be valid
        return SessionStore(session_key=session_key).create_model_instance(data or {})

    def test_serializer_no_extra_fields(self):
        session = self.make_session("walter_white")
        serialized_data = SessionSerializer(session).data

        self.assertEqual(
            {
                "session_key": "walter_white",
                "user_agent": None,
                "ip_address": None,
                "created_at": None,
                "last_active": None,
            },
            serialized_data,
        )

    def test_serializer_extra_fields(self):
        session = self.make_session(
            "walter_white",
            {
                "user_agent": "hank_schrader",
                "ip_address": "127.0.0.1",
                "created_at": "2000-01-01T12:00:00.000000",
                "last_active": "2025-01-01T12:00:00.000000",
            },
        )
        serialized_data = SessionSerializer(session).data

        self.assertEqual(
            {
                "session_key": "walter_white",
                "user_agent": "hank_schrader",
                "ip_address": "127.0.0.1",
                "created_at": "2000-01-01T12:00:00.000000",
                "last_active": "2025-01-01T12:00:00.000000",
            },
            serialized_data,
        )
