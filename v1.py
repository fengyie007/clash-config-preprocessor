import requests
import utils
import yaml
import re

from collections import OrderedDict

PRE_PROXY_GROUPS = ["DIRECT","REJECT"]

VERSION = "version"

PREPROCESSOR = "preprocessor"

CLASH_GENERAL = "clash-general"

PROXY_SOURCES = "proxy-sources"

PLAIN = "plain"

PROXY_GROUP_DISPATCH = "proxy-group-dispatch"

PATH = "path"

FILE = "file"

URL = "url"

NAME = "name"

TYPE = "type"

TARGET_MAP = "target-map"

TARGET_SKIP = "target-skip"

RULE_SKIP = "rule-skip"

RULE_SETS = "rule-sets"

RULE_LOWER = "rule"

RULE_SET = "RULE-SET"

PROXY = "Proxy"

RULE = "Rule"

RULES = "rules"

PROXY_GROUPS = "proxy-groups"

PROXIES = "proxies"

BACK_FLAT_PROXIES = "back-flat-proxies"

FLAT_PROXIES = "flat-proxies"

WHITE_REGEX = "white-regex"

BLACK_REGEX = "black-regex"

PROXIES_FILTERS = "proxies-filters"


def handle_v1(data: OrderedDict) -> OrderedDict:
    preprocessor: OrderedDict = data[PREPROCESSOR]

    if preprocessor is None or preprocessor[VERSION] != 1:
        raise utils.ParseException("Version != 1")

    result: OrderedDict = OrderedDict()

    general_block: OrderedDict = data[CLASH_GENERAL]
    result.update(general_block)

    proxy_sources_dicts: list = data[PROXY_SOURCES]
    proxies: list = []

    for item in proxy_sources_dicts:
        if item[TYPE] == URL:
            proxies += load_url_proxies(item[URL])
        elif item[TYPE] == FILE:
            proxies += load_file_proxies(item[PATH])
        elif item[TYPE] == PLAIN:
            proxies.append(load_plain_proxies(item))

    proxy_group_dispatch_dicts: list = data[PROXY_GROUP_DISPATCH]
    proxy_groups: list = []

    for item in proxy_group_dispatch_dicts:
        group_data: OrderedDict = item.copy()
        ps: list = []

        if PROXIES_FILTERS not in item:
            black_regex = None
            white_regex = None
        else:
            black_regex = re.compile(item[PROXIES_FILTERS].get(BLACK_REGEX, ''))
            white_regex = re.compile(item[PROXIES_FILTERS].get(WHITE_REGEX, ''))

        if FLAT_PROXIES in item and item[FLAT_PROXIES] is not None:
            ps.extend(item[FLAT_PROXIES])

        for p in proxies:
            p_name: str = formatName(p[NAME])
            if black_regex and white_regex and white_regex.fullmatch(p_name) and not black_regex.fullmatch(p_name):
                ps.append(p_name)

        if BACK_FLAT_PROXIES in item and item[BACK_FLAT_PROXIES] is not None:
            ps.extend(item[BACK_FLAT_PROXIES])

        group_data.pop(PROXIES_FILTERS, None)
        group_data.pop(FLAT_PROXIES, None)
        group_data.pop(BACK_FLAT_PROXIES, None)

        if len(ps) > 0:
            group_data[PROXIES] = ps

        if PROXIES in group_data and len(group_data[PROXIES]) > 0:
            proxy_groups.append(group_data)

    group_names = []+PRE_PROXY_GROUPS
    for group in proxy_groups:
        group_names.append(group[NAME])
    for group in proxy_groups:
        if group[NAME] == PROXY:
            local_proxies = group[PROXIES]
            need_removes = []
            for group_name in local_proxies:
                if group_name not in group_names:
                    need_removes.append(group_name)
            for i in range(len(local_proxies)-1,-1,-1):
                if local_proxies[i] in need_removes:
                    local_proxies.pop(i)

    rule_sets_dicts: list = data[RULE_SETS]
    rule_sets: dict = {}

    if not rule_sets_dicts is None:
        for item in rule_sets_dicts:
            item_name: str = formatName(item[NAME])
            item_type: str = item[TYPE]
            item_map: dict = {}
            item_rule_skip = item.get(RULE_SKIP, {})
            item_target_skip = item.get(TARGET_SKIP, {})
            for target_map_element in item.get(TARGET_MAP, {}):
                kv: list = target_map_element.split(",")
                item_map[kv[0]] = kv[1]

            if item_type == URL:
                rule_sets[item_name] = load_url_rule_set(item[URL], item_map, item_rule_skip, item_target_skip)
            elif item_type == FILE:
                rule_sets[item_name] = load_file_rule_set(item[PATH], item_map, item_rule_skip, item_target_skip)

    rules: list = []
    keysets: set = set()

    for rule in data[RULE_LOWER]:
        rule_str = str(rule)
        if rule_str.startswith(RULE_SET):
            rule_set_name = rule_str.split(",")[1]
            for newrule in rule_sets[rule_set_name]:
                rule_parts: list = newrule.split(",")[0:2]
                key = ",".join(rule_parts)
                if key not in keysets:
                    rules.append(newrule)
                    keysets.add(key)
        else:
            rule_parts: list = rule_str.split(",")[0:2]
            key = ",".join(rule_parts)
            if key not in keysets:
                rules.append(rule_str)
                keysets.add(key)

    result[PROXIES] = proxies
    result[PROXY_GROUPS] = proxy_groups
    result[RULES] = rules

    return result


def formatName(input: str):
    return input.replace("\t", '')


def load_url_proxies(url: str) -> OrderedDict:
    data = requests.get(url)
    data_yaml: OrderedDict = yaml.load(data.content.decode(), Loader=yaml.Loader)
    proxies = load_properties(data_yaml, PROXY, PROXIES)
    for item in proxies:
        item[NAME] = formatName(item[NAME])
    return proxies


def load_properties(dict, prop1, prop2):
    result = dict.get(prop1)
    if not result:
        result = dict.get(prop2)
    return result


def load_file_proxies(path: str) -> OrderedDict:
    with open(path, "r") as f:
        data_yaml: OrderedDict = yaml.load(f, Loader=yaml.Loader)

    return load_properties(data_yaml, PROXY, PROXIES)


def load_plain_proxies(data: OrderedDict) -> OrderedDict:
    return data["data"]


def load_url_rule_set(url: str, targetMap: dict, skipRule: set, skipTarget: set) -> list:
    data = yaml.load(requests.get(url).content, Loader=yaml.Loader)
    result: list = []

    rules = load_properties(data, RULE, RULES)
    for rule in rules:
        splits = str(rule).split(",")
        if len(splits) > 2:
            original_target = str(rule).split(",")[2:3][0]
        else:
            original_target = ''
        map_to: str = targetMap.get(original_target)
        if splits[0] not in skipRule and original_target not in skipTarget:
            if not map_to is None:
                result.append(str(rule).replace(original_target, map_to))
            else:
                result.append(str(rule))

    return result


def load_file_rule_set(path: str, targetMap: dict, skipRule: set, skipTarget: set) -> list:
    with open(path, "r") as f:
        data = yaml.load(f, Loader=yaml.Loader)
    result: list = []

    rules = load_properties(data, RULE, RULES)
    for rule in rules:
        original_target = str(rule).split(",")[-1]
        map_to: str = targetMap.get(original_target)
        if str(rule).split(',')[0] not in skipRule and original_target not in skipTarget:
            if not map_to is None:
                result.append(str(rule).replace(original_target, map_to))
            else:
                result.append(rule)

    return result
