"""Input validation helpers for MetricsHub.

These exist precisely so that user-supplied values are constrained before they
reach a query. Whether a SAST tool *recognises* that is another matter.
"""

# The only columns a caller is ever allowed to sort or group by. Anything not in
# this set is rejected — there is no way for arbitrary text to get through.
ALLOWED_SORT_COLUMNS = {"name", "email", "created_at", "status", "last_login"}

ALLOWED_INTERVALS = {"day", "week", "month", "quarter"}


def is_allowed_sort(column):
    """Guard-style validator: returns True/False, caller is expected to bail out.

    Note for the exercise: because this only *reports* validity and the caller
    raises on False, a taint engine cannot easily tell that the value is safe by
    the time it reaches the query. See `safe_sort` for the form a scanner can
    follow.
    """
    return column in ALLOWED_SORT_COLUMNS


def safe_sort(column):
    """Sanitiser-style validator: returns a guaranteed-safe value.

    Either the input is in the allow-list (returned unchanged) or it is replaced
    with a safe default. The return value can ONLY ever be one of a fixed set of
    literals, so it is safe to interpolate — and a taint rule can be taught to
    treat this function as a sanitiser.
    """
    return column if column in ALLOWED_SORT_COLUMNS else "created_at"
