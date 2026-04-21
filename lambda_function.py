import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from dotenv import load_dotenv
from google import genai
from google.genai import types

load_dotenv()

logger = logging.getLogger(__name__)
if not logging.getLogger().handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )
logger.setLevel(logging.INFO)

MODEL_CANDIDATES = [
    "gemini-2.5-flash",
    "gemini-2.5-flash-lite",
    "gemini-2.5-pro",
    "gemini-3-flash",
    "gemini-3.1-flash-lite",
]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def compact_dict(data: Dict[str, Any]) -> Dict[str, Any]:
    return {key: value for key, value in data.items() if value not in (None, "", [], {})}


def is_retryable_error(error_message: str) -> bool:
    lowered = error_message.lower()
    retryable_markers = ("503", "429", "high demand", "too many requests", "unavailable")
    return any(marker in lowered for marker in retryable_markers)


def sanitize_model_text(raw_text: str) -> str:
    cleaned = raw_text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("```", 2)[1]
        cleaned = cleaned.removeprefix("json").strip()

    first_brace = cleaned.find("{")
    last_brace = cleaned.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        cleaned = cleaned[first_brace:last_brace + 1]
    return cleaned


def parse_enrichment_response(response: Any) -> Dict[str, Any]:
    raw_text = getattr(response, "text", "") or ""
    cleaned_text = sanitize_model_text(raw_text)
    return json.loads(cleaned_text)


def serialize_usage_metadata(usage_metadata: Any) -> Dict[str, Any]:
    if not usage_metadata:
        return {}

    fields = (
        "prompt_token_count",
        "candidates_token_count",
        "total_token_count",
        "thoughts_token_count",
        "cached_content_token_count",
        "tool_use_prompt_token_count",
        "traffic_type",
    )
    serialized: Dict[str, Any] = {}
    for field_name in fields:
        value = getattr(usage_metadata, field_name, None)
        if value is not None:
            serialized[field_name] = str(value) if field_name == "traffic_type" else value
    return serialized


def build_prompt(alert_data: Dict[str, Any]) -> str:
    return (
        "Analyze the following security alert and produce a JSON response with:\n"
        "- severity\n"
        "- impact\n"
        "- actions\n"
        "- patterns\n\n"
        "Requirements:\n"
        "- severity must be one of: Critical, High, Medium, Low\n"
        "- actions must be a list of concise recommended next steps\n"
        "- patterns must be a list of related behaviors, anomalies, or signals\n"
        "- return JSON only\n\n"
        f"Alert Data:\n{json.dumps(alert_data, indent=2)}"
    )


def build_failure_result(
    alert_data: Dict[str, Any],
    execution_log: Dict[str, Any],
    error_message: str,
    model_used: Optional[str] = None,
) -> Dict[str, Any]:
    execution_log.update(
        compact_dict(
            {
                "status": "failed",
                "completed_at_utc": utc_now_iso(),
                "duration_ms": int((time.perf_counter() - execution_log["timer_start"]) * 1000),
                "model_used": model_used,
                "failure_reason": error_message,
            }
        )
    )

    enriched_alert = {
        **alert_data,
        "ai_enrichment": {"error": error_message},
    }
    if model_used:
        enriched_alert["model_used"] = model_used

    logger.error(
        "Enrichment failed: %s",
        json.dumps(compact_dict({"model_used": model_used, "error": error_message}), default=str),
    )
    return {
        "enriched_alert": enriched_alert,
        "execution_log": finalize_execution_log(execution_log),
    }


def finalize_execution_log(execution_log: Dict[str, Any]) -> Dict[str, Any]:
    finalized = dict(execution_log)
    finalized.pop("timer_start", None)
    return finalized


def enrich_alert_with_gemini(
    alert_data: Dict[str, Any],
    max_retries: int = 3,
    backoff_factor: int = 2,
) -> Dict[str, Any]:
    prompt = build_prompt(alert_data)
    total_attempts = max_retries * len(MODEL_CANDIDATES)
    delay_seconds = 1
    execution_log: Dict[str, Any] = {
        "provider": "google-genai",
        "status": "in_progress",
        "started_at_utc": utc_now_iso(),
        "prompt_characters": len(prompt),
        "requested_models": MODEL_CANDIDATES,
        "retry_policy": {
            "max_retries_per_model_cycle": max_retries,
            "backoff_factor": backoff_factor,
            "initial_delay_seconds": 1,
        },
        "attempts": [],
        "timer_start": time.perf_counter(),
    }

    for attempt_index in range(total_attempts):
        model = MODEL_CANDIDATES[attempt_index % len(MODEL_CANDIDATES)]
        attempt_number = attempt_index + 1
        attempt_started = time.perf_counter()
        attempt_log: Dict[str, Any] = {
            "attempt": attempt_number,
            "model": model,
            "started_at_utc": utc_now_iso(),
        }

        logger.info("Enrichment attempt %s/%s using %s", attempt_number, total_attempts, model)

        try:
            with genai.Client() as client:
                response = client.models.generate_content(
                    model=model,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json",
                        temperature=0.2,
                    ),
                )

            enrichment_data = parse_enrichment_response(response)
            usage_metadata = serialize_usage_metadata(getattr(response, "usage_metadata", None))
            total_duration_ms = int((time.perf_counter() - execution_log["timer_start"]) * 1000)
            attempt_duration_ms = int((time.perf_counter() - attempt_started) * 1000)
            response_text = getattr(response, "text", "") or ""

            attempt_log.update(
                compact_dict(
                    {
                        "status": "success",
                        "duration_ms": attempt_duration_ms,
                        "model_version": getattr(response, "model_version", None),
                        "response_id": getattr(response, "response_id", None),
                    }
                )
            )
            execution_log["attempts"].append(attempt_log)
            execution_log.update(
                compact_dict(
                    {
                        "status": "success",
                        "completed_at_utc": utc_now_iso(),
                        "duration_ms": total_duration_ms,
                        "attempt_count": attempt_number,
                        "model_used": model,
                        "model_version": getattr(response, "model_version", None),
                        "response_id": getattr(response, "response_id", None),
                        "token_usage": usage_metadata,
                        "output_metrics": {
                            "response_characters": len(response_text),
                            "actions_count": len(enrichment_data.get("actions", [])),
                            "patterns_count": len(enrichment_data.get("patterns", [])),
                        },
                    }
                )
            )

            logger.info(
                "Enrichment completed: %s",
                json.dumps(
                    compact_dict(
                        {
                            "model_used": model,
                            "duration_ms": total_duration_ms,
                            "response_id": getattr(response, "response_id", None),
                            "token_usage": usage_metadata,
                        }
                    ),
                    default=str,
                ),
            )

            enriched_alert = {
                **alert_data,
                "ai_enrichment": enrichment_data,
                "model_used": model,
            }
            return {
                "enriched_alert": enriched_alert,
                "execution_log": finalize_execution_log(execution_log),
            }
        except json.JSONDecodeError as exc:
            attempt_log.update(
                {
                    "status": "invalid_json",
                    "duration_ms": int((time.perf_counter() - attempt_started) * 1000),
                    "error": str(exc),
                }
            )
            execution_log["attempts"].append(attempt_log)
            logger.warning("Model %s returned invalid JSON on attempt %s", model, attempt_number)
        except Exception as exc:
            error_message = str(exc)
            attempt_log.update(
                {
                    "status": "error",
                    "duration_ms": int((time.perf_counter() - attempt_started) * 1000),
                    "error": error_message,
                }
            )
            execution_log["attempts"].append(attempt_log)

            if is_retryable_error(error_message) and attempt_number < total_attempts:
                attempt_log["status"] = "retrying"
                attempt_log["retry_delay_seconds"] = delay_seconds
                logger.warning(
                    "Model %s busy or rate-limited, retrying in %ss (attempt %s/%s)",
                    model,
                    delay_seconds,
                    attempt_number,
                    total_attempts,
                )
                time.sleep(delay_seconds)
                delay_seconds *= backoff_factor
                continue

            return build_failure_result(
                alert_data,
                execution_log,
                f"Failed to enrich with Gemini: {error_message}",
                model_used=model,
            )

    return build_failure_result(
        alert_data,
        execution_log,
        "All Gemini models were unavailable or returned invalid JSON after retries.",
    )


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    try:
        logger.info("Received event: %s", json.dumps(event))
        alert_data = event.get("alert", {})
        if not alert_data:
            raise ValueError("No alert data provided in event")

        enrichment_result = enrich_alert_with_gemini(alert_data)
        execution_log = enrichment_result["execution_log"]
        request_id = getattr(context, "aws_request_id", None)
        if request_id:
            execution_log["aws_request_id"] = request_id

        is_success = execution_log.get("status") == "success"
        response_body = {
            "message": "Alert enriched successfully" if is_success else "Alert enrichment failed",
            "enriched_alert": enrichment_result["enriched_alert"],
            "execution_log": execution_log,
        }
        return {
            "statusCode": 200 if is_success else 502,
            "body": json.dumps(response_body),
        }
    except Exception as exc:
        logger.error("Error processing alert: %s", str(exc))
        return {
            "statusCode": 500,
            "body": json.dumps(
                {
                    "error": str(exc),
                    "message": "Failed to enrich alert",
                }
            ),
        }


def format_lambda_response(result: Dict[str, Any]) -> str:
    status_code = result.get("statusCode", "n/a")
    try:
        body = json.loads(result.get("body", "{}"))
    except json.JSONDecodeError:
        return json.dumps(result, indent=2)

    enriched_alert = body.get("enriched_alert", {})
    ai_enrichment = enriched_alert.get("ai_enrichment", {})
    execution_log = body.get("execution_log", {})
    token_usage = execution_log.get("token_usage", {})

    summary_lines = [
        "=" * 72,
        "AI Alert Enrichment Report",
        "=" * 72,
        f"HTTP Status   : {status_code}",
        f"Message       : {body.get('message', 'n/a')}",
        f"Alert ID      : {enriched_alert.get('id', 'n/a')}",
        f"Model Used    : {execution_log.get('model_used', enriched_alert.get('model_used', 'n/a'))}",
        f"Model Version : {execution_log.get('model_version', 'n/a')}",
        f"Duration      : {execution_log.get('duration_ms', 'n/a')} ms",
        f"Response ID   : {execution_log.get('response_id', 'n/a')}",
        (
            "Token Usage   : "
            f"prompt={token_usage.get('prompt_token_count', 'n/a')} | "
            f"output={token_usage.get('candidates_token_count', 'n/a')} | "
            f"total={token_usage.get('total_token_count', 'n/a')}"
        ),
        "",
        "Severity",
        f"  {ai_enrichment.get('severity', 'n/a')}",
        "",
        "Impact",
        f"  {ai_enrichment.get('impact', 'n/a')}",
        "",
        "Recommended Actions",
    ]

    actions = ai_enrichment.get("actions", [])
    if actions:
        summary_lines.extend(f"  {index}. {action}" for index, action in enumerate(actions, start=1))
    else:
        summary_lines.append("  None")

    summary_lines.extend(["", "Related Patterns"])
    patterns = ai_enrichment.get("patterns", [])
    if patterns:
        summary_lines.extend(f"  {index}. {pattern}" for index, pattern in enumerate(patterns, start=1))
    else:
        summary_lines.append("  None")

    summary_lines.extend(["", "Execution Attempts"])
    for attempt in execution_log.get("attempts", []):
        summary_lines.append(
            "  "
            f"Attempt {attempt.get('attempt', '?')}: "
            f"{attempt.get('model', 'n/a')} -> {attempt.get('status', 'unknown')} "
            f"({attempt.get('duration_ms', 'n/a')} ms)"
        )
        if attempt.get("error"):
            summary_lines.append(f"    Error: {attempt['error']}")

    summary_lines.extend(["", "Structured Payload", json.dumps(body, indent=2)])
    return "\n".join(summary_lines)


if __name__ == "__main__":
    sample_event = {
        "alert": {
            "id": "alert-001",
            "message": "Suspicious login detected",
            "timestamp": "2026-04-21T12:00:00Z",
        }
    }
    lambda_result = lambda_handler(sample_event, None)
    print(format_lambda_response(lambda_result))
