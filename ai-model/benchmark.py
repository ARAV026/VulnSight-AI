from __future__ import annotations

from collections import Counter


def precision_recall_f1(tp: int, fp: int, fn: int) -> dict[str, float]:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": precision, "recall": recall, "f1": f1}


def benchmark(predictions: list[str], labels: list[str]) -> dict[str, float]:
    tp = fp = fn = 0
    for pred, label in zip(predictions, labels):
        if pred == label:
            tp += 1
        else:
            fp += 1
            fn += 1
    return precision_recall_f1(tp, fp, fn)


if __name__ == "__main__":
    example_predictions = ["SQL Injection", "Cross-Site Scripting", "Benign", "CSRF"]
    example_labels = ["SQL Injection", "Cross-Site Scripting", "Benign", "Benign"]
    print(benchmark(example_predictions, example_labels))
