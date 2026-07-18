import math
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "adapter"))

from dirextalk_knowledge.embedding import E5Embedder
from dirextalk_knowledge.errors import DependencyUnavailable


class FakeTokenizer:
    def __init__(self):
        self.calls = []

    def encode(self, text, max_length):
        self.calls.append((text, max_length))
        return [10, 20, 0], [1, 1, 0], [0, 0, 0]


class FakeRuntime:
    def __init__(self, bad_dimension=False, nonfinite=False):
        self.bad_dimension = bad_dimension
        self.nonfinite = nonfinite

    def infer(self, input_ids, attention_mask, token_type_ids):
        dimension = 383 if self.bad_dimension else 384
        first = [0.0] * dimension
        second = [0.0] * dimension
        third = [10.0] * dimension
        first[0] = math.nan if self.nonfinite else 2.0
        second[1] = 2.0
        return [first, second, third]


class EmbeddingTests(unittest.TestCase):
    def test_e5_prefix_masked_mean_and_l2_normalization(self):
        tokenizer = FakeTokenizer()
        embedder = E5Embedder(tokenizer, FakeRuntime())
        passage = embedder.passage("document")
        query = embedder.query("question")
        self.assertEqual(
            tokenizer.calls,
            [("passage: document", 512), ("query: question", 512)],
        )
        self.assertEqual(len(passage), 384)
        self.assertAlmostEqual(passage[0], 1 / math.sqrt(2), places=12)
        self.assertAlmostEqual(passage[1], 1 / math.sqrt(2), places=12)
        self.assertAlmostEqual(sum(value * value for value in query), 1.0, places=12)
        self.assertTrue(all(math.isfinite(value) for value in query))

    def test_rejects_wrong_dimension_and_nonfinite_output(self):
        for runtime in (FakeRuntime(bad_dimension=True), FakeRuntime(nonfinite=True)):
            with self.subTest(runtime=runtime.__dict__):
                with self.assertRaises(DependencyUnavailable):
                    E5Embedder(FakeTokenizer(), runtime).query("question")


if __name__ == "__main__":
    unittest.main()
