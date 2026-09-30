import git
import pytest

from common.exceptions import ValidationAppError

from .services import _clone_error_message, validate_repository_url

pytestmark = pytest.mark.django_db


class TestRepositoryUrlValidation:
    def test_valid_https_github_url_accepted(self):
        validate_repository_url("https://github.com/org/repo.git")  # should not raise

    def test_ssh_url_rejected(self):
        with pytest.raises(ValidationAppError):
            validate_repository_url("git@github.com:org/repo.git")

    def test_file_url_rejected(self):
        with pytest.raises(ValidationAppError):
            validate_repository_url("file:///etc/passwd")

    def test_local_loopback_url_still_requires_https_scheme(self):
        # Not an SSRF allowlist by itself, but confirms non-https schemes
        # (which could be used to reach internal services) are rejected outright.
        with pytest.raises(ValidationAppError):
            validate_repository_url("http://169.254.169.254/latest/meta-data/")

    def test_empty_url_rejected(self):
        with pytest.raises(ValidationAppError):
            validate_repository_url("")


class TestCloneErrorMessage:
    def test_not_found_is_classified(self):
        exc = git.GitCommandError(["git", "clone"], 128, stderr="remote: Repository not found.")
        assert "not found" in _clone_error_message(exc).lower()

    def test_auth_failure_is_classified(self):
        exc = git.GitCommandError(["git", "clone"], 128, stderr="fatal: Authentication failed")
        assert "authentication" in _clone_error_message(exc).lower()
