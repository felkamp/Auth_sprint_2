import unittest
from http import HTTPStatus

import requests
from flask_jwt_extended import create_access_token

from src.models.user import Permission
from tests.functional.test_cases.base import BaseUnitTest
from tests.functional.test_data import data
from tests.functional.utils.utils import api_url_wth_path as _u


class TestPermissions(BaseUnitTest, unittest.TestCase):
    def setUp(self):
        super(TestPermissions, self).setUp()

    def test_access_is_allowed(self):
        access_token = create_access_token(
            identity=data.users[1]["id"],
            additional_claims={"perms": Permission.VIEW | Permission.CREATE},
        )
        headers = {"Authorization": f"Bearer {access_token}"}
        res = requests.get(
            url=_u("/roles"), headers=headers, params={"page": 1, "size": 10}
        )

        self.assertTrue(len(data.roles) == len(res.json()))
        self.assertTrue(HTTPStatus.OK == res.status_code)

    def test_access_denied(self):
        access_token = create_access_token(
            identity=data.users[0]["id"], additional_claims={"perms": Permission.VIEW}
        )
        headers = {"Authorization": f"Bearer {access_token}"}
        res = requests.post(url=_u("/roles"), headers=headers)

        self.assertTrue(HTTPStatus.FORBIDDEN == res.status_code)
