-- Exact repeated facts are idempotent while observations at new times remain historical.
CREATE UNIQUE INDEX observations_exact_fact
ON observations(
    deployment_id,
    subject_type,
    ifnull(subject_id, -1),
    fact_type,
    fact_value_json,
    confidence,
    inferred,
    source,
    observed_at
);
