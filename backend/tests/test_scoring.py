from risk_runner.models import Finding, Repository
from risk_runner.scoring import aggregate_repo_score, score_finding


def repo(**kw):
    base = dict(full_name="a/b", criticality=3, exposure="internal", data_sensitivity="internal", compliance=[], revenue_impacting=False)
    return Repository(**{**base, **kw})


def finding(**kw):
    base = dict(scan_type="sca", severity="high", cvss_score=None, epss_score=None, in_kev=False, ai_adjustment=0.0)
    return Finding(**{**base, **kw})


def test_business_context_raises_score():
    low_ctx, high_ctx = repo(criticality=1), repo(criticality=5, exposure="internet", data_sensitivity="restricted", compliance=["PCI"])
    a, b = finding(), finding()
    score_finding(a, low_ctx)
    score_finding(b, high_ctx)
    assert b.risk_score > a.risk_score + 20


def test_kev_and_epss_drive_likelihood():
    r = repo()
    kev, hot, cold = finding(cvss_score=7.5, in_kev=True), finding(cvss_score=7.5, epss_score=0.9), finding(cvss_score=7.5, epss_score=0.0001)
    for f in (kev, hot, cold):
        score_finding(f, r)
    assert kev.risk_score > hot.risk_score > cold.risk_score
    assert kev.score_factors["likelihood_source"] == "kev"


def test_ai_adjustment_is_applied_and_clamped():
    f = finding(cvss_score=10.0, in_kev=True, ai_adjustment=15.0)
    score_finding(f, repo(criticality=5, exposure="internet", data_sensitivity="restricted"))
    assert f.risk_score == 100.0
    assert f.base_score < 100


def test_repo_aggregate():
    assert aggregate_repo_score([]) == 0
    assert aggregate_repo_score([90]) > aggregate_repo_score([50, 50, 50])
    assert aggregate_repo_score([90, 60]) > aggregate_repo_score([90])
