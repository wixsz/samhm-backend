from __future__ import annotations

import json
import logging
import math
import pickle
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from transformers import AutoModelForSequenceClassification, AutoTokenizer

from app.core.config import settings

logger = logging.getLogger("SAMHM.SentimentService")

SUPPORTED_MODEL_EXTENSIONS = (".joblib", ".pkl", ".pickle")
HUGGINGFACE_WEIGHT_FILES = ("model.safetensors", "pytorch_model.bin")
MODEL_METADATA_FILES = ("metadata.json", "model_config.json", "config.json")
MODEL_LABEL_FILES = ("labels.json", "label_map.json", "classes.json")

DEFAULT_HF_MODEL_ID = "omar89090/samhm-distilbert-7class"

NEGATIVE_HINTS = {
    "negative",
    "depression",
    "depressed",
    "anxiety",
    "stress",
    "bi polar",
    "distress",
    "risk",
    "suicide",
    "suicidal",
    "hopeless",
    "sad",
    "fear",
    "anger",
    "angry",
}
POSITIVE_HINTS = {
    "positive",
    "support",
    "supportive",
    "hope",
    "hopeful",
    "joy",
    "happy",
    "calm",
    "well",
    "wellness",
    "love",
    "surprise",
}
NEUTRAL_HINTS = {"neutral", "mixed", "uncertain", "other", "unknown", "normal"}

EMOTION_KEYWORD_HINTS = {
    "Depression": [
        "depressed",
        "hopeless",
        "worthless",
        "empty",
        "numb",
        "give up",
        "sad",
        "miserable",
        "lonely",
        "crying",
    ],
    "Anxiety": [
        "anxious",
        "panic",
        "panicked",
        "racing thoughts",
        "nervous",
        "fear",
        "worried",
        "uneasy",
        "restless",
        "can't calm down",
        "cannot calm down",
    ],
    "Stress": [
        "stress",
        "stressed",
        "stressful",
        "overwhelmed",
        "burnout",
        "exhausted",
        "mad",
        "angry",
        "frustrated",
        "irritated",
    ],
    "Suicidal": ["suicide", "suicidal", "kill myself", "want to die", "end my life"],
    "Bi-Polar": ["manic", "mania", "bipolar", "bi-polar"],
}


@dataclass(slots=True)
class LoadedSentimentModel:
    predictor: Any
    vectorizer: Any | None
    labels: list[str]
    model_name: str
    model_version: str
    model_path: Path
    runtime_kind: str = "serialized_model"
    tokenizer: Any | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class SentimentInferenceResult:
    sentiment: str
    confidence: float
    raw_label: str | None
    model_name: str
    model_version: str
    label_scores: dict[str, float] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    explainability: dict[str, Any] | None = None

    @property
    def emotion_label(self) -> str | None:
        if not self.raw_label:
            return None

        normalized_raw = SentimentService.normalize_label(self.raw_label)
        if normalized_raw == self.sentiment:
            return None

        return str(self.raw_label)


class SentimentService:
    MODEL_NAME = settings.MODEL_NAME
    MODEL_VERSION = settings.MODEL_VERSION_OVERRIDE or "baseline_rule_v1"

    _load_attempted = False
    _runtime: LoadedSentimentModel | None = None
    _load_error: str | None = None

    @classmethod
    def analyze_batch(cls, texts: list[str]) -> list[SentimentInferenceResult]:
        runtime = cls._ensure_runtime()

        if runtime is None:
            return [cls._predict_with_rules(text) for text in texts]

        if runtime.runtime_kind == "huggingface_transformers":
            return cls._predict_batch_huggingface(texts, runtime)

        return [cls._predict_with_runtime(text, runtime) for text in texts]

    @classmethod
    def get_model_name(cls) -> str:
        runtime = cls._ensure_runtime()
        if runtime is not None:
            return runtime.model_name
        return cls.MODEL_NAME

    @classmethod
    def get_model_version(cls) -> str:
        runtime = cls._ensure_runtime()
        if runtime is not None:
            return runtime.model_version
        return cls.MODEL_VERSION

    @classmethod
    def get_runtime_status(cls) -> dict[str, Any]:
        runtime = cls._ensure_runtime()
        if runtime is None:
            return {
                "status": "fallback",
                "model_name": cls.MODEL_NAME,
                "model_version": cls.MODEL_VERSION,
                "load_error": cls._load_error,
            }

        return {
            "status": "loaded",
            "model_name": runtime.model_name,
            "model_version": runtime.model_version,
            "model_path": cls._relative_model_path(runtime.model_path),
            "runtime_kind": runtime.runtime_kind,
        }

    @classmethod
    def warm_up(cls) -> None:
        status = cls.get_runtime_status()
        if status["status"] == "loaded":
            logger.info(
                "Sentiment model loaded | name=%s version=%s path=%s runtime=%s",
                status["model_name"],
                status["model_version"],
                status["model_path"],
                status.get("runtime_kind"),
            )
            return

        logger.warning(
            "Sentiment model not loaded; using fallback rules | reason=%s",
            status.get("load_error") or "no_model_file_found",
        )

    @classmethod
    def normalize_label(cls, label: Any) -> str:
        return str(label).strip().replace("_", " ").replace("-", " ").lower()

    @classmethod
    def map_label_to_sentiment(cls, label: Any) -> str:
        normalized = cls.normalize_label(label)

        if any(token in normalized for token in NEGATIVE_HINTS):
            return "negative"
        if any(token in normalized for token in POSITIVE_HINTS):
            return "positive"
        if any(token in normalized for token in NEUTRAL_HINTS):
            return "neutral"

        return "neutral"

    @classmethod
    def _ensure_runtime(cls) -> LoadedSentimentModel | None:
        if cls._load_attempted:
            return cls._runtime

        cls._load_attempted = True
        try:
            cls._runtime = cls._load_runtime()
        except Exception as exc:
            cls._runtime = None
            cls._load_error = str(exc)
            logger.exception("Unable to load configured sentiment model")

        return cls._runtime

    @classmethod
    def _load_runtime(cls) -> LoadedSentimentModel | None:
        candidate_dirs = cls._candidate_model_dirs()
        model_path = cls._resolve_model_file()

        if model_path is not None:
            loaded_object = cls._load_serialized_object(model_path)
            if isinstance(loaded_object, LoadedSentimentModel):
                cls.MODEL_NAME = loaded_object.model_name
                cls.MODEL_VERSION = loaded_object.model_version
                cls._load_error = None
                return loaded_object

            metadata = cls._load_metadata(model_path)
            labels = cls._load_labels(model_path, metadata)

            predictor = loaded_object
            vectorizer = None

            if isinstance(loaded_object, dict):
                predictor = (
                    loaded_object.get("pipeline")
                    or loaded_object.get("model")
                    or loaded_object.get("classifier")
                    or loaded_object.get("estimator")
                    or loaded_object.get("predictor")
                    or loaded_object
                )
                vectorizer = loaded_object.get("vectorizer")
                if not labels:
                    labels = cls._extract_labels_from_mapping(loaded_object.get("labels"))

            if not hasattr(predictor, "predict"):
                raise RuntimeError(
                    f"serialized model '{model_path.name}' does not expose a predict() method"
                )

            model_name = (
                metadata.get("model_name")
                or getattr(predictor, "model_name", None)
                or settings.MODEL_NAME
            )
            model_version = (
                metadata.get("model_version")
                or getattr(predictor, "model_version", None)
                or settings.MODEL_VERSION_OVERRIDE
                or model_path.stem
            )

            cls.MODEL_NAME = str(model_name)
            cls.MODEL_VERSION = str(model_version)
            cls._load_error = None

            return LoadedSentimentModel(
                predictor=predictor,
                vectorizer=vectorizer,
                labels=labels,
                model_name=str(model_name),
                model_version=str(model_version),
                model_path=model_path,
                metadata=metadata,
            )

        local_model = Path(settings.MODEL_DIR) / settings.MODEL_NAME

        if False and local_model.exists():

            logger.iwnfo("Loading local HuggingFace model from %s", local_model)
            runtime = cls._load_huggingface_model(local_model)
            cls.MODEL_NAME = runtime.model_name
            cls.MODEL_VERSION = runtime.model_version
            cls._load_error = None
            return runtime

        searched_dirs = ", ".join(str(path) for path in candidate_dirs) or str(
            cls._resolve_optional_path(settings.MODEL_DIR) or (cls._project_root() / "app" / "models")
        )
        logger.info(
            "No local serialized model found in %s. Falling back to HuggingFace download.",
            searched_dirs,
        )

        runtime = cls._load_huggingface_model()
        cls.MODEL_NAME = runtime.model_name
        cls.MODEL_VERSION = runtime.model_version
        cls._load_error = None
        return runtime

    @classmethod
    def _resolve_model_file(cls) -> Path | None:
        configured_path = cls._resolve_optional_path(settings.MODEL_FILE)
        if configured_path is not None and configured_path.is_file():
            return configured_path
        if configured_path is not None and configured_path.is_dir():
            return configured_path

        for directory in cls._candidate_model_dirs():
            huggingface_path = cls._resolve_huggingface_dir(directory)
            if huggingface_path is not None:
                return huggingface_path
            for extension in SUPPORTED_MODEL_EXTENSIONS:
                matches = sorted(directory.rglob(f"*{extension}"))
                if matches:
                    return matches[0]

        return None

    @classmethod
    def _resolve_huggingface_dir(cls, directory: Path) -> Path | None:
        if not directory.exists():
            return None

        if cls._is_huggingface_model_dir(directory):
            return directory

        for child in sorted(path for path in directory.iterdir() if path.is_dir()):
            if cls._is_huggingface_model_dir(child):
                return child

        return None

    @classmethod
    def _is_huggingface_model_dir(cls, directory: Path) -> bool:
        if not directory.is_dir():
            return False

        has_config = (directory / "config.json").is_file()
        has_weights = any(
            (directory / name).is_file() for name in HUGGINGFACE_WEIGHT_FILES
        )
        has_tokenizer = any(
            (directory / name).is_file()
            for name in ("tokenizer.json", "tokenizer_config.json", "vocab.txt")
        )
        return has_config and has_weights and has_tokenizer

    @classmethod
    def _candidate_model_dirs(cls) -> list[Path]:
        configured_dir = cls._resolve_optional_path(settings.MODEL_DIR)
        candidates = [configured_dir] if configured_dir is not None else []

        project_root = cls._project_root()
        candidates.extend([project_root / "app" / "models", project_root / "models"])

        deduped: list[Path] = []
        for path in candidates:
            if path is None:
                continue
            resolved = path.resolve()
            if resolved.exists() and resolved not in deduped:
                deduped.append(resolved)

        return deduped

    @classmethod
    def _project_root(cls) -> Path:
        return Path(__file__).resolve().parents[2]

    @classmethod
    def _resolve_optional_path(cls, value: str | None) -> Path | None:
        if not value:
            return None

        path = Path(value)
        if path.is_absolute():
            return path

        return cls._project_root() / path

    @classmethod
    def _load_serialized_object(cls, model_path: Path) -> Any:
        if model_path.is_dir():
            return cls._load_huggingface_model(model_path)

        suffix = model_path.suffix.lower()

        if suffix == ".joblib":
            try:
                import joblib
            except ImportError as exc:
                raise RuntimeError(
                    "joblib is required to load .joblib model files"
                ) from exc

            return joblib.load(model_path)

        try:
            with model_path.open("rb") as model_file:
                return pickle.load(model_file)
        except Exception as pickle_error:
            try:
                import joblib
            except ImportError:
                raise RuntimeError(
                    "pickle load failed and joblib is not installed for fallback loading"
                ) from pickle_error

            return joblib.load(model_path)

    @classmethod
    def _load_huggingface_model(
        cls,
        model_dir: Path | None = None,
    ) -> LoadedSentimentModel:
        try:
            import torch
        except ImportError as exc:
            raise RuntimeError(
                "torch is required to run Hugging Face inference"
            ) from exc

        if model_dir is not None and model_dir.exists():
            logger.info("Loading local Hugging Face model from %s", model_dir)
            tokenizer = AutoTokenizer.from_pretrained(str(model_dir), local_files_only=True)
            predictor = AutoModelForSequenceClassification.from_pretrained(
                str(model_dir),
                local_files_only=True,
            )
            model_name = model_dir.name
            model_path = model_dir
            metadata = cls._load_metadata(model_dir)
        else:
            hf_model_id = (
                getattr(settings, "HF_MODEL_ID", None)
                or getattr(settings, "MODEL_HF_ID", None)
                or DEFAULT_HF_MODEL_ID
            )
            logger.info("Downloading sentiment model from HuggingFace: %s", hf_model_id)
            tokenizer = AutoTokenizer.from_pretrained(hf_model_id)
            predictor = AutoModelForSequenceClassification.from_pretrained(hf_model_id)
            model_name = hf_model_id
            model_path = Path("huggingface_download")
            metadata = {"source": "huggingface", "model_id": hf_model_id}

        predictor.eval()

        config = predictor.config
        labels = cls._extract_labels_from_mapping(getattr(config, "id2label", None))

        metadata.setdefault(
            "transformers_model_type", getattr(config, "model_type", None)
        )
        metadata.setdefault("num_labels", getattr(config, "num_labels", None))

        model_version = (
            metadata.get("model_version")
            or getattr(config, "transformers_version", None)
            or settings.MODEL_VERSION_OVERRIDE
            or "hf_runtime_v1"
        )

        return LoadedSentimentModel(
            predictor=predictor,
            vectorizer=None,
            labels=labels,
            model_name="MH_EMOTION_DISTILBERT_7CLASS",
            model_version=str(model_version),
            model_path=model_path,
            runtime_kind="huggingface_transformers",
            tokenizer=tokenizer,
            metadata=metadata,
        )

    @classmethod
    def _load_metadata(cls, model_path: Path) -> dict[str, Any]:
        configured_path = cls._resolve_optional_path(settings.MODEL_METADATA_FILE)
        candidate_paths: list[Path] = []
        if configured_path is not None:
            candidate_paths.append(configured_path)
        base_path = model_path if model_path.is_dir() else model_path.parent
        candidate_paths.extend(base_path / name for name in MODEL_METADATA_FILES)

        for path in candidate_paths:
            if not path.exists() or not path.is_file():
                continue

            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                logger.warning("Ignoring invalid model metadata file at %s", path)

        return {}

    @classmethod
    def _load_labels(cls, model_path: Path, metadata: dict[str, Any]) -> list[str]:
        labels = cls._extract_labels_from_mapping(metadata.get("labels"))
        if labels:
            return labels

        configured_path = cls._resolve_optional_path(settings.MODEL_LABELS_FILE)
        candidate_paths: list[Path] = []
        if configured_path is not None:
            candidate_paths.append(configured_path)
        base_path = model_path if model_path.is_dir() else model_path.parent
        candidate_paths.extend(base_path / name for name in MODEL_LABEL_FILES)

        for path in candidate_paths:
            if not path.exists() or not path.is_file():
                continue

            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                logger.warning("Ignoring invalid labels file at %s", path)
                continue

            labels = cls._extract_labels_from_mapping(data)
            if labels:
                return labels

        return []

    @classmethod
    def _extract_labels_from_mapping(cls, value: Any) -> list[str]:
        if isinstance(value, list):
            return [str(item) for item in value]

        if isinstance(value, dict):
            if all(str(key).isdigit() for key in value.keys()):
                return [
                    str(item[1])
                    for item in sorted(value.items(), key=lambda item: int(item[0]))
                ]

            if "classes" in value and isinstance(value["classes"], list):
                return [str(item) for item in value["classes"]]

            if all(isinstance(item, str) for item in value.values()):
                try:
                    return [
                        str(item[1])
                        for item in sorted(value.items(), key=lambda item: int(item[0]))
                    ]
                except ValueError:
                    return [str(item) for item in value.values()]

        return []

    @classmethod
    def _predict_with_runtime(
        cls,
        text: str,
        runtime: LoadedSentimentModel,
    ) -> SentimentInferenceResult:
        if runtime.runtime_kind == "huggingface_transformers":
            return cls._predict_with_huggingface(text, runtime)

        features: Any = [text]
        if runtime.vectorizer is not None:
            features = runtime.vectorizer.transform([text])

        predicted = runtime.predictor.predict(features)
        resolved_label = cls._resolve_predicted_label(predicted[0], runtime)
        label_scores = cls._collect_label_scores(runtime, features)
        confidence = label_scores.get(resolved_label)

        if confidence is None:
            confidence = cls._estimate_confidence_from_decision_function(
                runtime, features
            )

        if confidence is None:
            confidence = 0.75

        metadata = {
            "runtime": "serialized_model",
            "model_path": cls._relative_model_path(runtime.model_path),
        }
        metadata.update(runtime.metadata)

        explainability = None
        if label_scores:
            top_scores = sorted(
                label_scores.items(),
                key=lambda item: item[1],
                reverse=True,
            )[:3]
            explainability = {
                "top_scores": [
                    {"label": label, "score": round(score, 6)}
                    for label, score in top_scores
                ]
            }

        return SentimentInferenceResult(
            sentiment=cls.map_label_to_sentiment(resolved_label),
            confidence=max(0.0, min(float(confidence), 1.0)),
            raw_label=resolved_label,
            model_name=runtime.model_name,
            model_version=runtime.model_version,
            label_scores=label_scores,
            metadata=metadata,
            explainability=explainability,
        )

    @classmethod
    def _predict_with_huggingface(
        cls,
        text: str,
        runtime: LoadedSentimentModel,
    ) -> SentimentInferenceResult:
        try:
            import torch
        except ImportError as exc:
            raise RuntimeError(
                "torch is required to run Hugging Face inference"
            ) from exc

        if runtime.tokenizer is None:
            raise RuntimeError("tokenizer not loaded for Hugging Face runtime")

        encoded = runtime.tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=512,
            padding=True,
        )

        with torch.no_grad():
            outputs = runtime.predictor(**encoded)
            probabilities = torch.softmax(outputs.logits, dim=-1)[0].tolist()

        labels = runtime.labels or [str(index) for index in range(len(probabilities))]
        if len(labels) < len(probabilities):
            labels.extend(
                str(index) for index in range(len(labels), len(probabilities))
            )

        label_scores = {
            str(label): float(score) for label, score in zip(labels, probabilities)
        }
        label_scores = cls._apply_keyword_adjustments(text, label_scores)
        resolved_label = max(label_scores.items(), key=lambda item: item[1])[0]

        metadata = {
            "runtime": runtime.runtime_kind,
            "model_path": cls._relative_model_path(runtime.model_path),
        }
        metadata.update(runtime.metadata)

        top_scores = sorted(
            label_scores.items(),
            key=lambda item: item[1],
            reverse=True,
        )[:3]

    @classmethod
    def _predict_batch_huggingface(
        cls,
        texts: list[str],
        runtime: LoadedSentimentModel,
    ) -> list[SentimentInferenceResult]:

        import torch

        tokenizer = runtime.tokenizer
        model = runtime.predictor

        encoded = tokenizer(
            texts,
            return_tensors="pt",
            truncation=True,
            padding=True,
            max_length=512,
        )

        with torch.no_grad():
            outputs = model(**encoded)
            probs = torch.softmax(outputs.logits, dim=-1).tolist()

        labels = runtime.labels or [str(i) for i in range(len(probs[0]))]

        results = []

        for text, probabilities in zip(texts, probs):

            label_scores = {
                str(label): float(score)
                for label, score in zip(labels, probabilities)
            }

            resolved_label = max(label_scores.items(), key=lambda x: x[1])[0]

            results.append(
                SentimentInferenceResult(
                    sentiment=cls.map_label_to_sentiment(resolved_label),
                    confidence=float(label_scores[resolved_label]),
                    raw_label=resolved_label,
                    model_name=runtime.model_name,
                    model_version=runtime.model_version,
                    label_scores=label_scores,
                    metadata={"runtime": "batch_huggingface"},
                )
            )

        return results
    

    @classmethod
    def _apply_keyword_adjustments(
        cls,
        text: str,
        label_scores: dict[str, float],
    ) -> dict[str, float]:
        lowered = text.lower()
        cue_counts = {
            label: sum(1 for keyword in keywords if keyword in lowered)
            for label, keywords in EMOTION_KEYWORD_HINTS.items()
        }

        if max(cue_counts.values(), default=0) == 0:
            return label_scores

        adjusted = dict(label_scores)
        top_label = max(adjusted.items(), key=lambda item: item[1])[0]

        if top_label in {"Normal", "Other"}:
            top_cap = 0.18
        else:
            top_cap = None

        for cue_label, cue_strength in cue_counts.items():
            if cue_strength <= 0 or cue_label not in adjusted:
                continue

            if top_cap is not None:
                adjusted[cue_label] = max(
                    adjusted[cue_label],
                    0.68 + min(cue_strength, 2) * 0.12,
                )
            else:
                adjusted[cue_label] = max(
                    adjusted[cue_label],
                    min(0.88, adjusted[cue_label] + cue_strength * 0.12),
                )

        if top_cap is not None and top_label in adjusted:
            adjusted[top_label] = min(adjusted[top_label], top_cap)

        total = sum(max(value, 0.0) for value in adjusted.values()) or 1.0
        return {label: max(value, 0.0) / total for label, value in adjusted.items()}

    @classmethod
    def _resolve_predicted_label(
        cls,
        value: Any,
        runtime: LoadedSentimentModel,
    ) -> str:
        if isinstance(value, (int, float)) and float(value).is_integer():
            index = int(value)
            if 0 <= index < len(runtime.labels):
                return runtime.labels[index]

        string_value = str(value)
        if string_value.isdigit():
            index = int(string_value)
            if 0 <= index < len(runtime.labels):
                return runtime.labels[index]

        return string_value

    @classmethod
    def _collect_label_scores(
        cls,
        runtime: LoadedSentimentModel,
        features: Any,
    ) -> dict[str, float]:
        if not hasattr(runtime.predictor, "predict_proba"):
            return {}

        probabilities = runtime.predictor.predict_proba(features)
        row = probabilities[0]
        classes = list(getattr(runtime.predictor, "classes_", runtime.labels))
        if not classes:
            classes = list(range(len(row)))

        scores: dict[str, float] = {}
        for label, score in zip(classes, row):
            resolved_label = cls._resolve_predicted_label(label, runtime)
            scores[str(resolved_label)] = float(score)

        return scores

    @classmethod
    def _estimate_confidence_from_decision_function(
        cls,
        runtime: LoadedSentimentModel,
        features: Any,
    ) -> float | None:
        if not hasattr(runtime.predictor, "decision_function"):
            return None

        decision = runtime.predictor.decision_function(features)
        raw_value = decision[0]

        if isinstance(raw_value, (list, tuple)):
            magnitude = max(abs(float(item)) for item in raw_value)
        else:
            magnitude = abs(float(raw_value))

        return 1 / (1 + math.exp(-magnitude))

    @classmethod
    def _predict_with_rules(cls, text: str) -> SentimentInferenceResult:
        text_lower = text.lower()
        if any(word in text_lower for word in ["sad", "depressed", "hopeless"]):
            sentiment = "negative"
            confidence = 0.25
            label_scores = {"negative": 0.25, "neutral": 0.5, "positive": 0.25}
        elif any(word in text_lower for word in ["happy", "great", "excited"]):
            sentiment = "positive"
            confidence = 0.90
            label_scores = {"positive": 0.9, "neutral": 0.08, "negative": 0.02}
        else:
            sentiment = "neutral"
            confidence = 0.50
            label_scores = {"neutral": 0.5, "positive": 0.25, "negative": 0.25}

        metadata: dict[str, Any] = {"runtime": "fallback_rule_engine"}
        if cls._load_error:
            metadata["load_error"] = cls._load_error

        return SentimentInferenceResult(
            sentiment=sentiment,
            confidence=confidence,
            raw_label=sentiment,
            model_name=cls.MODEL_NAME,
            model_version=cls.MODEL_VERSION,
            label_scores=label_scores,
            metadata=metadata,
            explainability={
                "matched_keywords": [
                    token
                    for token in [
                        "sad",
                        "depressed",
                        "hopeless",
                        "happy",
                        "great",
                        "excited",
                    ]
                    if token in text_lower
                ]
            },
        )

    @classmethod
    def _relative_model_path(cls, path: Path) -> str:
        try:
            return str(path.resolve().relative_to(cls._project_root()))
        except ValueError:
            return str(path)