from unittest import TestCase

from hidp.accounts import mailers


class TestBaseMailer(TestCase):
    def test_default_context(self):
        mailer = mailers.BaseMailer(base_url="https://example.com/")
        self.assertEqual(
            mailer.get_context(),
            {
                "base_url": "https://example.com",
            },
        )

    def test_get_recipients(self):
        with self.assertRaises(NotImplementedError) as cm:
            mailers.BaseMailer(base_url="https://example.com/").get_recipients()
        self.assertEqual(
            cm.exception.args[0], "Method get_recipients must be implemented"
        )

    def test_send(self):
        with self.assertRaises(NotImplementedError) as cm:
            mailers.BaseMailer(base_url="https://example.com/").send()
        self.assertEqual(
            cm.exception.args[0], "Attribute subject_template_name must be set"
        )
