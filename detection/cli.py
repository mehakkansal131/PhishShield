"""Command-line entry points for local PhishShield detection and evaluation."""

import argparse
import json

from detection.evaluator import print_evaluation_report
from detection.email_parser import parse_eml_file
from detection.scorer import PhishingDetector
from simulation.campaign_service import DEFAULT_DATASET_PATH


def main():
    parser = argparse.ArgumentParser(
        description="Run the local PhishShield educational email detector."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    evaluate_parser = subparsers.add_parser(
        "evaluate",
        help="Evaluate against the existing labelled Module 1 JSON dataset.",
    )
    evaluate_parser.add_argument(
        "--dataset",
        default=str(DEFAULT_DATASET_PATH),
        help="Path to a labelled JSON dataset.",
    )

    sample_parser = subparsers.add_parser(
        "sample",
        help="Analyze one sample selected from the existing dataset.",
    )
    sample_parser.add_argument("email_id", help="Dataset email_id to analyze.")
    sample_parser.add_argument(
        "--dataset",
        default=str(DEFAULT_DATASET_PATH),
        help="Path to the Module 1 JSON dataset.",
    )
    eml_parser = subparsers.add_parser(
        "eml",
        help="Analyze a local .eml file without contacting links or opening attachments.",
    )
    eml_parser.add_argument("path", help="Path to a local .eml file.")

    args = parser.parse_args()
    if args.command == "evaluate":
        print_evaluation_report(args.dataset)
        return
    if args.command == "eml":
        print(json.dumps(PhishingDetector().analyze(parse_eml_file(args.path)), indent=2))
        return

    with open(args.dataset, encoding="utf-8") as dataset_file:
        samples = json.load(dataset_file)
    for sample in samples:
        if sample.get("email_id") == args.email_id:
            print(json.dumps(PhishingDetector().analyze(sample), indent=2))
            return
    parser.error(f"email_id {args.email_id!r} was not found in the selected dataset.")


if __name__ == "__main__":
    main()
