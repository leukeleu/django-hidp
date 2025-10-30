from io import StringIO
from pathlib import Path

from rest_framework.test import APITestCase

from django.conf import settings
from django.core.management import call_command

existing_schema_path = Path(
    settings.BASE_DIR / "packages" / "hidp" / "docs" / "openapi" / "schema.json"
)


class TestSchema(APITestCase):
    def test_schema(self):
        schema_output = StringIO()
        call_command("spectacular", format="openapi-json", stdout=schema_output)

        # remove added trailing newline
        generated_schema = schema_output.getvalue()[:-1]

        existing_schema = existing_schema_path.read_text()

        self.assertEqual(
            generated_schema,
            existing_schema,
            msg="Schema file needs to be regenerated.",
        )
