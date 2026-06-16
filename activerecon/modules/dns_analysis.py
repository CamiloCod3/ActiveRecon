import logging

import dns.resolver


def _record_value(record_type, answer):
    if record_type == "A":
        return answer.address
    if record_type == "MX":
        return answer.exchange.to_text()
    return answer.to_text()


def analyze_dns(target):
    """
    Analyzes DNS records for the target.
    """
    logging.info("Starting DNS analysis")
    dns_records = {}
    errors = {}

    for record_type in ("A", "MX", "TXT"):
        try:
            dns_records[record_type] = [
                _record_value(record_type, answer)
                for answer in dns.resolver.resolve(target, record_type)
            ]
        except Exception as e:
            logging.error(f"DNS {record_type} lookup failed: {e}")
            dns_records[record_type] = []
            errors[record_type] = str(e)

    if errors:
        dns_records["errors"] = errors

    return dns_records
