"""Tests of the use case that grants and revokes application access."""

import pytest

from auth_service.application import audit_actions
from auth_service.application.use_cases.grant_application_access import (
    GrantApplicationAccessUseCase,
)
from auth_service.domain.exceptions import (
    AccountNotFoundError,
    ApplicationNotFoundError,
)
from tests.credentials import TEST_EMAIL
from tests.fakes import FakeClock, InMemoryUnitOfWork, make_user


@pytest.fixture
def use_case(
    unit_of_work: InMemoryUnitOfWork,
    clock: FakeClock,
) -> GrantApplicationAccessUseCase:
    """Provide the use case over the in-memory unit of work.

    Parameters
    ----------
    unit_of_work : InMemoryUnitOfWork
        In-memory unit of work.
    clock : FakeClock
        Frozen clock.

    Returns
    -------
    GrantApplicationAccessUseCase
        Use case under test.
    """
    return GrantApplicationAccessUseCase(unit_of_work=unit_of_work, clock=clock)


def test_grant_gives_access_and_is_audited(
    use_case: GrantApplicationAccessUseCase,
    unit_of_work: InMemoryUnitOfWork,
) -> None:
    """Granting access makes the user able to use the application.

    Parameters
    ----------
    use_case : GrantApplicationAccessUseCase
        Use case under test.
    unit_of_work : InMemoryUnitOfWork
        In-memory unit of work.

    Returns
    -------
    None
    """
    user = unit_of_work.users.add(make_user())
    granted = use_case.execute(TEST_EMAIL.upper(), "finbrain")
    assert granted.id == user.id
    assert unit_of_work.application_access.has_active_access(user.id, "finbrain")
    assert unit_of_work.audit_log.actions == [audit_actions.APPLICATION_ACCESS_GRANTED]


def test_revoke_removes_access(
    use_case: GrantApplicationAccessUseCase,
    unit_of_work: InMemoryUnitOfWork,
) -> None:
    """Revoking access takes it away and is audited as a revocation.

    Parameters
    ----------
    use_case : GrantApplicationAccessUseCase
        Use case under test.
    unit_of_work : InMemoryUnitOfWork
        In-memory unit of work.

    Returns
    -------
    None
    """
    user = unit_of_work.users.add(make_user())
    use_case.execute(TEST_EMAIL, "finbrain")
    use_case.execute(TEST_EMAIL, "finbrain", revoke=True)
    assert not unit_of_work.application_access.has_active_access(user.id, "finbrain")
    last_action = unit_of_work.audit_log.actions[-1]
    assert last_action == audit_actions.APPLICATION_ACCESS_REVOKED


def test_unknown_account_is_refused(
    use_case: GrantApplicationAccessUseCase,
) -> None:
    """An e-mail without an account cannot receive access.

    Parameters
    ----------
    use_case : GrantApplicationAccessUseCase
        Use case under test.

    Returns
    -------
    None
    """
    with pytest.raises(AccountNotFoundError):
        use_case.execute(TEST_EMAIL, "finbrain")


def test_unknown_or_inactive_application_is_refused(
    use_case: GrantApplicationAccessUseCase,
    unit_of_work: InMemoryUnitOfWork,
) -> None:
    """Only applications in the active catalog can be granted.

    Parameters
    ----------
    use_case : GrantApplicationAccessUseCase
        Use case under test.
    unit_of_work : InMemoryUnitOfWork
        In-memory unit of work.

    Returns
    -------
    None
    """
    unit_of_work.users.add(make_user())
    with pytest.raises(ApplicationNotFoundError):
        use_case.execute(TEST_EMAIL, "inexistente")
    assert unit_of_work.audit_log.actions == []
