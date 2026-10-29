# Paired evaluation

`cases.json` defines six pairs / twelve artificial inert inputs and human
semantic labels. Scripts in generated cases are data for the scanner; never
execute them or install their dependencies.

```text
python tools/evaluate_pairs.py --output-dir out/pairs
```

This generates source cases, actual audit records, pending review templates,
and `evaluation_report.json`. Static checks cover exact rule IDs and selected
evidence origins. They do not score the agent's semantic judgment.

For a model evaluation, give the Agent only each case's source and audit,
plus the Skill instructions. Keep expected labels out of its prompt. Save its
actual completed reviews as `CASE_ID.json` in a separate directory, then:

```text
python tools/evaluate_pairs.py --output-dir out/pairs_reviewed --reviews out/agent_reviews
```

Missing/invalid reviews remain explicit. Semantic accuracy is null until all
cases have completed, validated reviews. Do not fill templates with expected
labels and present the result as measured model performance. This small,
handcrafted set is a regression suite, not a real-world security benchmark.
