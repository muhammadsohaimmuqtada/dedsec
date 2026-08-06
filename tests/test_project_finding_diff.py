import unittest

from dedsec.core.research_pipeline import ResearchPipeline
from dedsec.core.runtime import ScanContext


class ProjectFindingDiffTests(unittest.TestCase):
    def test_candidate_to_verified_is_changed_state_not_unrelated_new_object(self):
        first_context = ScanContext.build("https://example.com", "example.com")
        second_context = ScanContext.build("https://example.com", "example.com")
        try:
            first = ResearchPipeline(first_context)
            first.ingest_correlation(
                {
                    "hypotheses": [
                        {
                            "source": "exposures",
                            "type": "sensitive-exposure",
                            "title": "Potential exposed configuration",
                            "url": "https://example.com/config.json",
                            "severity": "HIGH",
                            "confidence": "hypothesis",
                            "evidence_ids": ["ev-old"],
                        }
                    ]
                }
            )
            previous = first.workspace.snapshot()

            second = ResearchPipeline(second_context)
            second.ingest_correlation(
                {
                    "verified_findings": [
                        {
                            "source": "exposures",
                            "type": "sensitive-exposure",
                            "title": "Potential exposed configuration",
                            "url": "https://example.com/config.json",
                            "severity": "HIGH",
                            "confidence": "verified",
                            "evidence_ids": ["ev-new-1", "ev-new-2"],
                        }
                    ]
                }
            )
            diff = second.workspace.diff(previous)
            self.assertEqual(diff["observations"]["new"], [])
            self.assertEqual(diff["observations"]["removed"], [])
            self.assertEqual(len(diff["observations"]["changed"]), 1)
            changed = diff["observations"]["changed"][0]
            self.assertEqual(changed["before"]["classification"], "candidate")
            self.assertEqual(changed["after"]["classification"], "verified-finding")
            # Scan-specific evidence IDs are not persisted in the stable project observation.
            self.assertNotIn("ev-old", str(changed))
            self.assertNotIn("ev-new-1", str(changed))
        finally:
            first_context.close()
            second_context.close()


if __name__ == "__main__":
    unittest.main()
