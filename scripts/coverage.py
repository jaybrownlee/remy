"""Print catalog coverage against the pinned HIPAA framework."""

from remy.recommendations.catalog import SUPPORTED_CHECK_IDS
from remy.recommendations.framework import SOURCE_URL, check_ids, citations_for


def main() -> None:
    checks = check_ids()
    supported = checks & SUPPORTED_CHECK_IDS
    print("# HIPAA recommendation coverage\n")
    print(f"Source: [Prowler 5.42.0 framework]({SOURCE_URL}).\n")
    print(
        f"{len(supported)} of {len(checks)} framework checks have guidance handlers. "
        "This counts implementation coverage, not validated fixes or compliance.\n"
    )
    print(
        "All mappings are upstream Prowler mappings requiring applicability review. "
        "Unsupported findings remain visible in reports.\n"
    )
    print("| Check | Guidance handler | Upstream HIPAA mapping |")
    print("| --- | --- | --- |")
    for check in sorted(checks):
        sections = "; ".join(c.section for c in citations_for(check))
        status = "Available; review required" if check in supported else "Missing"
        print(f"| {check} | {status} | {sections} |")
    print(
        "\nAdditional handlers outside this framework: "
        + ", ".join(sorted(SUPPORTED_CHECK_IDS - checks))
        + "."
    )


if __name__ == "__main__":
    main()
