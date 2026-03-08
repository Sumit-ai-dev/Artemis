#!/usr/bin/env python3
import random
import re
from typing import Any, Dict, List, Optional

import more_itertools
from karton.core import Task

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.crawling import (
    get_injectable_parameters,
    get_links_and_resources_on_same_domain,
)
from artemis.http_requests import HTTPResponse
from artemis.module_base import ArtemisBase
from artemis.modules.data.parameters import URL_PARAMS
from artemis.modules.data.static_extensions import STATIC_EXTENSIONS
from artemis.orm_injection_data import ORM_ERROR_MESSAGES, NOSQL_OPERATOR_PAYLOADS
from artemis.task_utils import get_target_url


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.HIGH)
class OrmInjectionDetector(ArtemisBase):
    """
    Module for detecting ORM injection and NoSQL injection vulnerabilities.

    Covers:
    - Error-based detection for Java (Hibernate/JPA), PHP (Doctrine/Eloquent),
      Python (Django ORM, SQLAlchemy), Node.js (Prisma, Sequelize, Mongoose),
      Ruby (Active Record) and Go (Gorm).
    - Operator injection for NoSQL databases (MongoDB) using bracket-syntax
      payloads (e.g. param[$ne]=1) and JSON object payloads.
    """

    num_retries = Config.Miscellaneous.SLOW_MODULE_NUM_RETRIES
    identity = "orm_injection_detector"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    @staticmethod
    def _strip_query_string(url: str) -> str:
        import urllib.parse

        url_parsed = urllib.parse.urlparse(url)
        return urllib.parse.urlunparse(url_parsed._replace(query="", fragment=""))

    def _contains_orm_error(self, url: str, response: Optional[HTTPResponse]) -> str | None:
        if response is None:
            return None

        for pattern in ORM_ERROR_MESSAGES:
            if re.search(pattern, response.content):
                self.log.debug("Matched ORM error: %s on %s", pattern, url)
                return pattern
        return None

    def _inject_nosql_operator(self, base_url: str, param: str, payload: str) -> str:
        """
        Appends a NoSQL operator payload to a URL parameter.
        E.g. for param 'username' and payload '[$ne]=1':
            https://example.com/login?username[$ne]=1
        """
        separator = "&" if "?" in base_url else "?"
        return f"{base_url}{separator}{param}{payload}"

    def scan(self, urls: List[str], task: Task) -> List[Dict[str, Any]]:
        self.log.info("ORM injection scanning URLs: %s", urls)

        # A neutral payload that should not trigger errors
        not_error_payload = "-1"
        message: List[Dict[str, Any]] = []

        for current_url in urls:
            parameters = get_injectable_parameters(current_url)
            self.log.info("Obtained parameters: %s for url %s", parameters, current_url)

            # --- Error-based ORM detection ---
            # We inject a single-quote + double-quote payload to provoke ORM
            # query parse errors. Same strategy as sql_injection_detector, but
            # we match against ORM-framework error strings, not raw SQL strings.
            error_payload = "'\""
            for param_batch in more_itertools.batched(parameters + URL_PARAMS, 75):
                from urllib.parse import parse_qs, urlencode, urlparse, urlunparse, unquote

                parsed_url = urlparse(current_url)
                query_params = parse_qs(parsed_url.query)

                new_query_error = {k: [error_payload] for k in query_params}
                new_query_clean = {k: [not_error_payload] for k in query_params}
                # also inject our probe params from the batch
                for k in param_batch:
                    new_query_error[k] = [error_payload]
                    new_query_clean[k] = [not_error_payload]

                url_with_payload = urlunparse(
                    parsed_url._replace(query=urlencode(new_query_error, doseq=True))
                )
                url_without_payload = urlunparse(
                    parsed_url._replace(query=urlencode(new_query_clean, doseq=True))
                )

                error = self._contains_orm_error(
                    url_with_payload, self.forgiving_http_get(url_with_payload)
                )

                if (
                    not self._contains_orm_error(
                        url_without_payload, self.forgiving_http_get(url_without_payload)
                    )
                    and error
                ):
                    message.append(
                        {
                            "url": url_with_payload,
                            "matched_error": error,
                            "statement": "It appears that this URL is vulnerable to ORM injection (error-based)",
                            "code": "orm_injection",
                        }
                    )
                    if Config.Modules.SqlInjectionDetector.SQL_INJECTION_STOP_ON_FIRST_MATCH:
                        return message

            # --- NoSQL operator injection detection ---
            # We test each discovered parameter with MongoDB-style operator payloads.
            # A finding is reported when the server responds differently compared to
            # a clean request, which strongly indicates unsanitised NoSQL operator
            # passthrough. We check against ORM error strings here too, since
            # Mongoose/MongoDB sometimes surfaces them in the HTTP response.
            all_params = list(parameters) + list(URL_PARAMS)
            for param in all_params:
                clean_url = self._inject_nosql_operator(current_url, param, f"={not_error_payload}")
                clean_response = self.forgiving_http_get(clean_url)

                for nosql_payload in NOSQL_OPERATOR_PAYLOADS:
                    probe_url = self._inject_nosql_operator(current_url, param, nosql_payload)
                    probe_response = self.forgiving_http_get(probe_url)

                    orm_error = self._contains_orm_error(probe_url, probe_response)

                    if orm_error and not self._contains_orm_error(clean_url, clean_response):
                        message.append(
                            {
                                "url": probe_url,
                                "matched_error": orm_error,
                                "statement": (
                                    f"It appears that this URL is vulnerable to NoSQL operator injection "
                                    f"(parameter: {param}, payload: {nosql_payload})"
                                ),
                                "code": "nosql_injection",
                            }
                        )
                        if Config.Modules.SqlInjectionDetector.SQL_INJECTION_STOP_ON_FIRST_MATCH:
                            return message

        return message

    def run(self, current_task: Task) -> None:
        url = get_target_url(current_task)

        links = get_links_and_resources_on_same_domain(url)
        links.append(url)
        links = list(set(links) | set([self._strip_query_string(link) for link in links]))

        links = [
            link.split("#")[0]
            for link in links
            if not any(link.split("?")[0].lower().endswith(extension) for extension in STATIC_EXTENSIONS)
        ]

        random.shuffle(links)

        message = self.scan(urls=links[: Config.Miscellaneous.MAX_URLS_TO_SCAN], task=current_task)

        if message:
            status = TaskStatus.INTERESTING
            status_reason = ", ".join(
                set(f"{m.get('url')}: {m.get('statement')}" for m in message)
            )
        else:
            status = TaskStatus.OK
            status_reason = None

        self.db.save_task_result(
            task=current_task,
            status=status,
            status_reason=status_reason,
            data={"result": list(more_itertools.unique_everseen(message))},
        )


if __name__ == "__main__":
    OrmInjectionDetector().loop()
