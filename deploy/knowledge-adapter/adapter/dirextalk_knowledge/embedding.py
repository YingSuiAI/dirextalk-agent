"""Pinned multilingual-e5-small embedding with injectable tokenizer/runtime seams."""

from __future__ import annotations

import hashlib
import math
import stat
from pathlib import Path
from typing import Any, Protocol, Sequence

from . import MODEL_REVISION, VECTOR_DIMENSIONS
from .errors import DependencyUnavailable

MODEL_ROOT = Path("/opt/dirextalk/knowledge/current/model")
MODEL_PATH = MODEL_ROOT / "onnx/model.onnx"
TOKENIZER_PATH = MODEL_ROOT / "tokenizer.json"
MODEL_FILES = {
    "onnx/model.onnx": (
        470_268_510,
        "ca456c06b3a9505ddfd9131408916dd79290368331e7d76bb621f1cba6bc8665",
    ),
    "tokenizer.json": (
        17_082_730,
        "0b44a9d7b51c3c62626640cda0e2c2f70fdacdc25bbbd68038369d14ebdf4c39",
    ),
    "config.json": (
        655,
        "69137736cab8b8903a07fe8afaafdda25aac55415a12a55d1bffa9f581abf959",
    ),
    "tokenizer_config.json": (
        443,
        "a1d6bc8734a6f635dc158508bef000f8e2e5a759c7d92f984b2c86e5ff53425b",
    ),
    "special_tokens_map.json": (
        167,
        "d05497f1da52c5e09554c0cd874037a083e1dc1b9cfd48034d1c717f1afc07a7",
    ),
}


class Tokenizer(Protocol):
    def encode(self, text: str, max_length: int) -> tuple[list[int], list[int], list[int]]:
        ...


class Runtime(Protocol):
    def infer(
        self,
        input_ids: Sequence[int],
        attention_mask: Sequence[int],
        token_type_ids: Sequence[int],
    ) -> Sequence[Sequence[float]]:
        ...


class E5Embedder:
    def __init__(self, tokenizer: Tokenizer, runtime: Runtime) -> None:
        self._tokenizer = tokenizer
        self._runtime = runtime

    def passage(self, text: str) -> list[float]:
        return self._embed("passage: " + text)

    def query(self, text: str) -> list[float]:
        return self._embed("query: " + text)

    def _embed(self, prefixed: str) -> list[float]:
        input_ids, attention_mask, token_type_ids = self._tokenizer.encode(
            prefixed, max_length=512
        )
        if (
            not input_ids
            or len(input_ids) > 512
            or len(input_ids) != len(attention_mask)
            or len(input_ids) != len(token_type_ids)
            or any(item not in (0, 1) for item in attention_mask)
            or sum(attention_mask) == 0
        ):
            raise DependencyUnavailable("embedding")
        hidden = self._runtime.infer(input_ids, attention_mask, token_type_ids)
        if len(hidden) != len(attention_mask):
            raise DependencyUnavailable("embedding")
        pooled = [0.0] * VECTOR_DIMENSIONS
        count = 0
        for token, include in zip(hidden, attention_mask, strict=True):
            if len(token) != VECTOR_DIMENSIONS:
                raise DependencyUnavailable("embedding")
            if include:
                count += 1
                for index, value in enumerate(token):
                    numeric = float(value)
                    if not math.isfinite(numeric):
                        raise DependencyUnavailable("embedding")
                    pooled[index] += numeric
        if count == 0:
            raise DependencyUnavailable("embedding")
        pooled = [value / count for value in pooled]
        norm = math.sqrt(sum(value * value for value in pooled))
        if not math.isfinite(norm) or norm <= 0.0:
            raise DependencyUnavailable("embedding")
        result = [value / norm for value in pooled]
        if len(result) != VECTOR_DIMENSIONS or not all(map(math.isfinite, result)):
            raise DependencyUnavailable("embedding")
        return result


class ProductionTokenizer:
    def __init__(self) -> None:
        import tokenizers
        from tokenizers import Tokenizer as HFTokenizer

        if tokenizers.__version__ != "0.23.1":
            raise DependencyUnavailable("tokenizer")
        self._tokenizer = HFTokenizer.from_file(str(TOKENIZER_PATH))
        self._tokenizer.enable_truncation(max_length=512)

    def encode(self, text: str, max_length: int) -> tuple[list[int], list[int], list[int]]:
        if max_length != 512:
            raise DependencyUnavailable("tokenizer")
        encoded = self._tokenizer.encode(text, add_special_tokens=True)
        return list(encoded.ids), list(encoded.attention_mask), list(encoded.type_ids)


class ONNXRuntime:
    def __init__(self) -> None:
        import onnxruntime as ort
        import numpy as np

        if ort.__version__ != "1.27.0" or np.__version__ != "2.5.1":
            raise DependencyUnavailable("embedding_dependencies")

        options = ort.SessionOptions()
        options.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
        options.intra_op_num_threads = 2
        options.inter_op_num_threads = 1
        options.enable_mem_pattern = False
        self._session = ort.InferenceSession(
            str(MODEL_PATH), sess_options=options, providers=["CPUExecutionProvider"]
        )
        if self._session.get_providers() != ["CPUExecutionProvider"]:
            raise DependencyUnavailable("execution_provider")
        disable_fallback = getattr(self._session, "disable_fallback", None)
        if disable_fallback is not None:
            disable_fallback()
        self._input_names = {item.name for item in self._session.get_inputs()}
        self._numpy = np

    def infer(
        self,
        input_ids: Sequence[int],
        attention_mask: Sequence[int],
        token_type_ids: Sequence[int],
    ) -> Sequence[Sequence[float]]:
        inputs: dict[str, Any] = {
            "input_ids": self._numpy.asarray([input_ids], dtype=self._numpy.int64),
            "attention_mask": self._numpy.asarray(
                [attention_mask], dtype=self._numpy.int64
            ),
        }
        if "token_type_ids" in self._input_names:
            inputs["token_type_ids"] = self._numpy.asarray(
                [token_type_ids], dtype=self._numpy.int64
            )
        try:
            output = self._session.run(None, inputs)[0]
        except Exception as exc:
            raise DependencyUnavailable("embedding") from exc
        if getattr(output, "ndim", 0) != 3 or output.shape[0] != 1:
            raise DependencyUnavailable("embedding")
        return output[0].tolist()


def verify_model_files() -> None:
    for relative, (expected_size, expected_digest) in MODEL_FILES.items():
        path = MODEL_ROOT / relative
        try:
            stat_result = path.stat(follow_symlinks=False)
        except OSError as exc:
            raise DependencyUnavailable("model") from exc
        if not stat.S_ISREG(stat_result.st_mode) or stat_result.st_size != expected_size:
            raise DependencyUnavailable("model")
        digest = hashlib.sha256()
        try:
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
        except OSError as exc:
            raise DependencyUnavailable("model") from exc
        if digest.hexdigest() != expected_digest:
            raise DependencyUnavailable("model")


def production_embedder() -> E5Embedder:
    verify_model_files()
    return E5Embedder(ProductionTokenizer(), ONNXRuntime())


def model_status() -> dict[str, Any]:
    return {
        "model": "intfloat/multilingual-e5-small",
        "model_revision": MODEL_REVISION,
        "dimensions": VECTOR_DIMENSIONS,
        "execution_provider": "CPUExecutionProvider",
    }
