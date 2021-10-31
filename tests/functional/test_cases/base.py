from src import app, db
from tests.functional.utils.add_test_data import add_test_data


class BaseUnitTest:
    @classmethod
    def setUpClass(cls):
        cls.app = app
        cls.app_context = app.app_context()
        cls.app_context.push()
        db.drop_all()
        db.create_all()
        add_test_data()

    @classmethod
    def tearDownClass(cls):
        db.session.remove()
        db.drop_all()
        cls.app_context.pop()
