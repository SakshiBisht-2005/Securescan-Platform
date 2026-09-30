# The dashboard app is intentionally model-less: it aggregates data from
# projects, scanner, and vulnerabilities via read-only service queries
# (see apps/dashboard/services.py). Keeping it model-free avoids duplicated
# state that could drift out of sync with the source-of-truth tables.
