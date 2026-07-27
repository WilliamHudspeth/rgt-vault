"""Tests for pricing.cost_report and pricing.estimate_cost."""

import unittest

from internal.llm import pricing


class PricingTests(unittest.TestCase):
    def test_estimate_cost_for_mistral(self):
        # mistral-small-latest: 0.20/M in, 0.60/M out
        cost = pricing.estimate_cost("mistral", "mistral-small-latest", 1_000_000, 1_000_000)
        self.assertAlmostEqual(cost, 0.20 + 0.60, places=4)

    def test_estimate_cost_for_groq(self):
        # llama-3.3-70b-versatile: 0.59/M in, 0.79/M out
        cost = pricing.estimate_cost("groq", "llama-3.3-70b-versatile", 1_000_000, 1_000_000)
        self.assertAlmostEqual(cost, 0.59 + 0.79, places=4)

    def test_estimate_cost_for_ollama_is_free(self):
        cost = pricing.estimate_cost("ollama:qwen2.5:7b", "qwen2.5:7b", 1_000_000, 1_000_000)
        self.assertEqual(cost, 0.0)

    def test_estimate_cost_for_gemini_cli_is_free(self):
        cost = pricing.estimate_cost("gemini-cli", "default", 1_000_000, 1_000_000)
        self.assertEqual(cost, 0.0)

    def test_unknown_provider_defaults_to_free(self):
        cost = pricing.estimate_cost("some-new-provider", "some-new-model", 1000, 1000)
        self.assertEqual(cost, 0.0)

    def test_cost_report_aggregates(self):
        totals = {
            ("mistral", "mistral-small-latest"): {
                "calls": 10,
                "ok": 10,
                "input_tokens": 1_000_000,
                "output_tokens": 500_000,
                "latency_ms_total": 5000,
            },
            ("groq", "llama-3.3-70b-versatile"): {
                "calls": 5,
                "ok": 5,
                "input_tokens": 2_000_000,
                "output_tokens": 1_000_000,
                "latency_ms_total": 3000,
            },
            ("ollama:qwen2.5:7b", "qwen2.5:7b"): {
                "calls": 20,
                "ok": 20,
                "input_tokens": 100_000,
                "output_tokens": 50_000,
                "latency_ms_total": 200_000,
            },
        }
        report = pricing.cost_report(totals)
        # Mistral: 1M * 0.20/M + 0.5M * 0.60/M = 0.50
        # Groq:    2M * 0.59/M + 1M * 0.79/M = 1.97
        # Ollama:  0
        # Total:   2.47
        self.assertIn("0.500000", report)
        self.assertIn("1.970000", report)
        self.assertIn("2.470000", report)

    def test_cost_report_empty(self):
        self.assertEqual(pricing.cost_report({}), "no usage data")


if __name__ == "__main__":
    unittest.main()
