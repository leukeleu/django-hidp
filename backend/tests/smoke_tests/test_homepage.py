from http import HTTPStatus

from django.test import TestCase

# FIXME: This is an extremely basic test for example purposes.
#        Write better tests to ensure the application is working as expected.


class TestHomepage(TestCase):
    def test_homepage(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, HTTPStatus.OK)
