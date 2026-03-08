# type: ignore
from test.base import ArtemisModuleTestCase
from unittest.mock import MagicMock

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.http_requests import HTTPResponse
from artemis.modules.orm_injection_detector import OrmInjectionDetector


HOST = "test-apache-with-orm-injection"


class OrmInjectionDetectorIntegrationTest(ArtemisModuleTestCase):
    """Integration tests that run against the Docker test container."""

    karton_class = OrmInjectionDetector

    def _make_task(self, host: str = HOST, port: int = 80) -> Task:
        return Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={"host": host, "port": port},
        )

    def test_orm_injection_detected(self) -> None:
        """The Doctrine ORM error page should be flagged as INTERESTING."""
        task = self._make_task()
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list

        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        codes = [r["code"] for r in call.kwargs["data"]["result"]]
        self.assertTrue(
            any(c in ("orm_injection", "nosql_injection") for c in codes),
            msg=f"Expected orm_injection or nosql_injection in result codes, got: {codes}",
        )

    def test_no_false_positive_on_clean_page(self) -> None:
        """The safe not_vuln.php page must NOT produce an INTERESTING finding."""
        import unittest.mock as mock

        task = self._make_task()
        with mock.patch(
            "artemis.modules.orm_injection_detector.get_links_and_resources_on_same_domain",
            return_value=[f"http://{HOST}:80/not_vuln.php"],
        ):
            self.run_task(task)

        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.OK)


class OrmInjectionDetectorUnitTest(ArtemisModuleTestCase):
    """Unit tests for the core detection methods — no Docker needed."""

    karton_class = OrmInjectionDetector

    def _make_response(self, body: str) -> HTTPResponse:
        mock_response = MagicMock(spec=HTTPResponse)
        mock_response.content = body
        return mock_response

    def test_detects_hibernate_error(self) -> None:
        response = self._make_response(
            "org.hibernate.hql.internal.ast.QuerySyntaxException: unexpected token: ' near line 1"
        )
        self.assertIsNotNone(self.karton._contains_orm_error("http://example.com", response))

    def test_detects_doctrine_error(self) -> None:
        response = self._make_response(
            "[Syntax Error] line 0, col 42: Error: Expected Literal, got '''"
        )
        self.assertIsNotNone(self.karton._contains_orm_error("http://example.com", response))

    def test_detects_django_orm_error(self) -> None:
        response = self._make_response("django.db.utils.OperationalError: unrecognized token")
        self.assertIsNotNone(self.karton._contains_orm_error("http://example.com", response))

    def test_detects_sqlalchemy_error(self) -> None:
        response = self._make_response("sqlalchemy.exc.ProgrammingError: syntax error")
        self.assertIsNotNone(self.karton._contains_orm_error("http://example.com", response))

    def test_detects_mongoose_cast_error(self) -> None:
        response = self._make_response("Cast to ObjectId failed for value \"'\" at path \"_id\"")
        self.assertIsNotNone(self.karton._contains_orm_error("http://example.com", response))

    def test_detects_mongodb_operator_error(self) -> None:
        response = self._make_response("MongoServerError: unknown top level operator: $ne")
        self.assertIsNotNone(self.karton._contains_orm_error("http://example.com", response))

    def test_detects_prisma_error(self) -> None:
        response = self._make_response("PrismaClientKnownRequestError: invalid query")
        self.assertIsNotNone(self.karton._contains_orm_error("http://example.com", response))

    def test_no_false_positive_on_clean_response(self) -> None:
        response = self._make_response("<html><body><h1>Welcome!</h1></body></html>")
        self.assertIsNone(self.karton._contains_orm_error("http://example.com", response))

    def test_returns_none_for_none_response(self) -> None:
        self.assertIsNone(self.karton._contains_orm_error("http://example.com", None))

    def test_nosql_url_no_existing_params(self) -> None:
        result = self.karton._inject_nosql_operator("http://example.com/login", "u", "[$ne]=1")
        self.assertEqual(result, "http://example.com/login?u[$ne]=1")

    def test_nosql_url_with_existing_params(self) -> None:
        result = self.karton._inject_nosql_operator("http://example.com/login?foo=bar", "u", "[$ne]=1")
        self.assertEqual(result, "http://example.com/login?foo=bar&u[$ne]=1")
