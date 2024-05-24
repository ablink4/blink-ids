"""
Parses rules for the rules engine.  Currently understands "traditional" Snort rule format, e.g.:
    alert tcp any any -> any any (msg:"Test rule"; sid:XXXXX; rev:1;)
Currently does not support the 3 new rule formats in Snort3: service, file, file identification
"""

import os
import re

from ..logging_config.logging_config import logger

RULE_HEADER_PART_NUM = 7  # number of parts in a rule header


def parse_rules_from_directory(file_dir: str):
    """
    Parses rules from a directory.
    :param file_dir: directory containing the rules files
    :return: none
    """

    if not os.path.isdir(file_dir):
        raise ValueError("Directory does not exist")

    for filename in os.listdir(file_dir):
        if filename.endswith(".rules"):
            _parse_rules_from_file(os.path.join(file_dir, filename))


def _parse_rules_from_file(filename: str):
    """
    Parses rules from a file in Snort 3 rule format.
    :param filename: file containing the rules
    :return: none
    """

    if not os.path.isfile(filename):
        raise ValueError("File does not exist")

    with open(filename, "r") as file:
        for line in file:
            # Skip empty lines and comments
            if line.strip() == "" or line.startswith("#"):
                continue

            # TODO: support rules that span lines, which is valid (but uncommon)

            # try to split rule header from options; helps to filter snort3-specific rule types also
            line_parts = line.split('(')
            if len(line_parts) >= 2:
                rule_header = line_parts[0]

                # rule options may have parentheses in them, so join them all together, and strip off the trailing
                # closing parenthesis so the opening and closing parenthesis around the options are both removed.
                rule_options = "(".join(line_parts[1:]).strip()[:-1]
            else:
                _print_invalid_unsupported_rule_msg(line)
                continue

            rule_parts = re.split(r"\s+", rule_header.strip())
            if len(rule_parts) < RULE_HEADER_PART_NUM:
                _print_invalid_unsupported_rule_msg(line)
                continue

            action = rule_parts[0]
            protocol = rule_parts[1]
            src_addr = rule_parts[2]
            src_port = rule_parts[3]
            arrow = rule_parts[4]
            dst_addr = rule_parts[5]
            dst_port = rule_parts[6]
            opts = _parse_rule_options(rule_options)

            logger.debug(f"Action: {action}")
            logger.debug(f"Protocol: {protocol}")
            logger.debug(f"Source Address: {src_addr}")
            logger.debug(f"Source Port: {src_port}")
            logger.debug(f"Arrow: {arrow}")
            logger.debug(f"Destination Address: {dst_addr}")
            logger.debug(f"Destination Port: {dst_port}")
            logger.debug(f"Rule Options: {opts}")


def _parse_rule_options(options_str: str) -> {}:
    """
    Takes the rules options part of a rule and parses it into a dictionary of {option_name: criteria} pairs
    :param options_str: the options part of a rule
    :return: options as a dictionary of {option_name: criteria} pairs
    """

    http_sticky_buffer_rules = [
        "http_uri",
        "http_raw_uri",
        "http_header",
        "http_raw_header",
        "http_cookie",
        "http_raw_cookie",
        "http_client_body",
        "http_raw_body",
        "http_param",
        "http_method",
        "http_version",
        "http_stat_code",
        "http_stat_msg",
        "http_raw_request",
        "http_raw_status",
        "http_trailer",
        "http_raw_trailer",
        "http_true_ip"
    ]

    if any(option in options_str for option in http_sticky_buffer_rules):
        logger.info("Warning: HTTP sticky buffer rules are not supported, skipping rule.")
        return {}

    options = {}

    logger.info(f"full options string: {options_str}")

    option_parts = options_str.split(';')  # options are terminated with a semi-colon

    for opt in option_parts:
        parts = opt.split(':')

        if len(parts) >= 2:
            opt_name = parts[0].strip()
            opt_criteria = ':'.join(parts[1:])

            if opt_name in options:
                # TODO: there can be duplicate content options, need to handle this
                logger.info(f"Error parsing rule options, found duplicate option name: {opt_name}")
            else:
                options[opt_name] = opt_criteria
        else:
            logger.info(f"Error parsing rule options, couldn't find option name, option string was: {opt}")
            continue

    return options


def _print_invalid_unsupported_rule_msg(line):
    """
    Prints a usage/error message to explain what happened when rules are skipped.

    :param line:  The rule line that caused this message to be generated
    """
    logger.info(f"Invalid rule format, rule will be skipped. If this is a Snort3 rule format such as a service, file, or \
            file identification rule, these are not currently supported.  Rule line was: {line.strip()}.")
