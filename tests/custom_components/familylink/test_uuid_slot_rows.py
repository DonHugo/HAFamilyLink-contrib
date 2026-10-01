"""Weekly slot rows keyed by a UUID are resolved on their policy id (issue #183).

Some accounts key their weekly bedtime and school time slots with a plain UUID
instead of a CA* protobuf id. The read path already classified those rows by
policy id; the write path rejected them on the id prefix, fell back to the
static CAEQ codes, and Google answered 400 on every weekly bedtime write.
"""

from __future__ import annotations

from custom_components.familylink.client.api import FamilyLinkClient

BEDTIME_RULE = "802c3176-8b24-452c-9ccd-2b19aebe487c"
SCHOOL_RULE = "5c0d1f2e-1111-4222-8333-944455556666"
BEDTIME_MONDAY = "0b651fe5-35d3-4738-8cd8-6b508b201126"
BEDTIME_SUNDAY = "319bb0f6-e03c-4c95-930a-27493119ac10"
SCHOOL_MONDAY = "7a3e9c10-2b4d-4e6f-8a9b-0c1d2e3f4a5b"
ORPHAN_MONDAY = "deadbeef-0000-4000-8000-000000000001"


def _time_limit_data(*, orphan: bool = False) -> list:
    """An unwrapped timeLimit payload whose slots are UUID-keyed."""
    windows = [
        [BEDTIME_MONDAY, 1, 2, [20, 0], [8, 30], "1", "2", BEDTIME_RULE],
        [BEDTIME_SUNDAY, 7, 2, [20, 0], [8, 30], "1", "2", BEDTIME_RULE],
        [SCHOOL_MONDAY, 1, 2, [8, 0], [15, 0], "1", "2", SCHOOL_RULE],
    ]
    if orphan:
        # A UUID row that carries no policy id cannot be told apart: not taken
        windows = [[ORPHAN_MONDAY, 1, 2, [20, 0], [8, 30], "1", "2"]]
    return [
        [2, windows, "1", "2", 1],
        [[["CAEQAQ", 1, 2, 120, "1", "2"]]],
        None,
        None,
        [1],
        [[BEDTIME_RULE, 1, 2, ["1", 0]], [SCHOOL_RULE, 2, 2, ["1", 0]]],
    ]


def test_uuid_bedtime_slot_is_resolved_on_its_policy_id() -> None:
    assert FamilyLinkClient._find_weekly_bedtime_slot_id(_time_limit_data(), 1) == BEDTIME_MONDAY
    assert FamilyLinkClient._find_weekly_bedtime_slot_id(_time_limit_data(), 7) == BEDTIME_SUNDAY


def test_uuid_school_time_row_is_resolved_on_its_policy_id() -> None:
    row = FamilyLinkClient._find_weekly_school_time_row(_time_limit_data(), 1)

    assert row is not None
    assert row[0] == SCHOOL_MONDAY


def test_uuid_bedtime_row_is_never_taken_for_school_time() -> None:
    # Sunday has a bedtime slot only: no school time row must be found
    assert FamilyLinkClient._find_weekly_school_time_row(_time_limit_data(), 7) is None


def test_uuid_row_without_policy_id_is_not_taken() -> None:
    """A UUID decodes to nothing: without the policy id there is no way to tell, so no guess."""
    assert FamilyLinkClient._find_weekly_bedtime_slot_id(_time_limit_data(orphan=True), 1) is None


def test_ca_ids_still_resolve_by_decoded_type() -> None:
    """Accounts on CA* ids keep working without a policy id on the row."""
    data = [
        [2, [["CAEQAQ", 1, 2, [22, 0], [7, 0], "1", "2"]], "1", "2", 1],
        [[["CAEQAQ", 1, 2, 120, "1", "2"]]],
        None,
        None,
        [1],
        [],
    ]
    assert FamilyLinkClient._find_weekly_bedtime_slot_id(data, 1) == "CAEQAQ"
