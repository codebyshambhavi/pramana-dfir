"""Tests for the versioned correlation parameter registry (Role 1, Stage 2).

Covers loading, versioning, validation, counts, hashing, export and the fixture
contract. Nothing here touches the database, the network or the existing T5/T6
engines, except read-only consistency checks against T5's published constants.
"""
from __future__ import annotations

import ast
import copy
import importlib
import json
import re
from pathlib import Path

import pytest

from intelligence import config as intel_config
from intelligence.correlation import registry as R
from intelligence.correlation import vocabulary as V

# ``intelligence.correlate`` the *function* is re-exported by the package, so import the module explicitly.
t5 = importlib.import_module("intelligence.correlate")

PACKAGE_DIR = Path(R.__file__).resolve().parent


@pytest.fixture(scope="module")
def reg() -> R.Registry:
    return R.load_registry()


@pytest.fixture()
def doc() -> dict:
    """A fresh, mutable copy of the shipped registry document."""
    return R.load_registry().export()


def _errors(document: dict) -> list[str]:
    return R.validate_document(document)


def _param(document: dict, parameter_id: str) -> dict:
    return next(p for p in document["parameters"] if p["parameter_id"] == parameter_id)


# ---------------------------------------------------------------------------
# Loading and versions
# ---------------------------------------------------------------------------
class TestLoading:
    def test_default_load(self, reg):
        assert reg.registry_version == R.DEFAULT_REGISTRY_VERSION == "corr-registry-v1"
        assert reg.config_version == "corr-config-v1"

    def test_load_by_registry_version_and_file_tag_are_equal(self):
        a = R.load_registry("corr-registry-v1")
        b = R.load_registry("v1")
        assert a.registry_hash == b.registry_hash
        assert a.export() == b.export()

    def test_available_versions_lists_shipped_registry(self):
        assert "corr-registry-v1" in R.available_versions()

    @pytest.mark.parametrize("bad", ["", " ", "../registry_v1", "..", "v1/../v1", "v1\\x", "a" * 65, "bad version",
                                     "v1\n", "corr registry", "-v1", ".v1", "v1;rm", "%2e%2e"])
    def test_malformed_versions_are_rejected(self, bad):
        with pytest.raises(R.RegistryVersionError):
            R.load_registry(bad)

    @pytest.mark.parametrize("bad", [1, 1.5, b"v1", ["v1"], {"v": 1}, True])
    def test_non_string_versions_are_rejected(self, bad):
        with pytest.raises(R.RegistryVersionError):
            R.load_registry(bad)

    def test_unknown_version_lists_available(self):
        with pytest.raises(R.RegistryVersionError) as exc:
            R.load_registry("corr-registry-v999")
        assert "corr-registry-v1" in str(exc.value)

    def test_version_is_never_used_to_build_a_path(self, tmp_path):
        # A well-formed token that merely *looks* like a file name must not read arbitrary files.
        (tmp_path / "secret.json").write_text(json.dumps({"registry_version": "leak"}))
        with pytest.raises(R.RegistryVersionError):
            R.load_registry("secret", directory=tmp_path)

    def test_load_from_directory_by_tag_and_version(self, tmp_path, doc):
        doc["registry_version"] = "corr-registry-v7"
        (tmp_path / "registry_v7.json").write_text(json.dumps(doc), encoding="utf-8")
        assert R.load_registry("v7", directory=tmp_path).registry_version == "corr-registry-v7"
        assert R.load_registry("corr-registry-v7", directory=tmp_path).registry_version == "corr-registry-v7"
        assert R.available_versions(tmp_path) == ["corr-registry-v7"]

    def test_historical_versions_stay_loadable_side_by_side(self, tmp_path, doc):
        """An older configuration keeps its own hash and values after a newer one ships."""
        v1 = copy.deepcopy(doc)
        v2 = copy.deepcopy(doc)
        v2["registry_version"] = "corr-registry-v2"
        v2["config_version"] = "corr-config-v2"
        v2["change_reason"] = "test: raise EMAIL_EXACT weight"
        _param(v2, "EMAIL_EXACT")["weight"] = 0.33
        (tmp_path / "registry_v1.json").write_text(json.dumps(v1), encoding="utf-8")
        (tmp_path / "registry_v2.json").write_text(json.dumps(v2), encoding="utf-8")
        old = R.load_registry("corr-registry-v1", directory=tmp_path)
        new = R.load_registry("corr-registry-v2", directory=tmp_path)
        assert old.get("EMAIL_EXACT").weight == 0.30
        assert new.get("EMAIL_EXACT").weight == 0.33
        assert old.registry_hash != new.registry_hash
        assert old.config_version == "corr-config-v1" and new.config_version == "corr-config-v2"
        assert R.available_versions(tmp_path) == ["corr-registry-v1", "corr-registry-v2"]

    def test_invalid_json_file_is_a_validation_error(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        with pytest.raises(R.RegistryValidationError):
            R.load_registry_from_path(bad)

    def test_non_finite_numbers_are_refused(self, tmp_path):
        text = (PACKAGE_DIR / "registry_v1.json").read_text(encoding="utf-8").replace('"value": 0.6,', '"value": NaN,', 1)
        path = tmp_path / "nan.json"
        path.write_text(text, encoding="utf-8")
        with pytest.raises(ValueError):
            R.load_registry_from_path(path)

    def test_shipped_file_is_valid_json_and_has_no_validation_errors(self):
        document = json.loads((PACKAGE_DIR / "registry_v1.json").read_text(encoding="utf-8"))
        assert R.validate_document(document) == []


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
class TestValidation:
    def test_non_object_document(self):
        assert _errors([]) == ["registry document must be a JSON object"]

    def test_missing_top_level_keys_are_all_reported(self):
        errs = _errors({})
        assert len(errs) == len(R.TOP_LEVEL_REQUIRED_KEYS)

    def test_duplicate_parameter_ids(self, doc):
        doc["parameters"].append(copy.deepcopy(doc["parameters"][0]))
        errs = _errors(doc)
        assert any("duplicate parameter_id" in e and doc["parameters"][0]["parameter_id"] in e for e in errs)

    def test_duplicate_ids_rejected_by_constructor(self, doc):
        doc["parameters"].append(copy.deepcopy(doc["parameters"][0]))
        with pytest.raises(R.RegistryValidationError) as exc:
            R.Registry(doc)
        assert any("duplicate" in e for e in exc.value.errors)

    def test_all_errors_are_collected_not_just_the_first(self, doc):
        _param(doc, "EMAIL_EXACT")["weight"] = 7
        _param(doc, "FILENAME")["family"] = "BOGUS"
        doc["thresholds"]["T_REVIEW"]["value"] = 0.9
        errs = _errors(doc)
        assert len(errs) >= 3

    def test_unknown_parameter_field_is_rejected(self, doc):
        _param(doc, "EMAIL_EXACT")["surprise"] = 1
        assert any("unknown field" in e for e in _errors(doc))

    def test_missing_parameter_field_is_rejected(self, doc):
        del _param(doc, "EMAIL_EXACT")["missing_value_policy"]
        assert any("missing field 'missing_value_policy'" in e for e in _errors(doc))

    @pytest.mark.parametrize("pid", ["a", "lower_case", "1ABC", "HAS SPACE", "X" * 65, ""])
    def test_bad_parameter_id(self, doc, pid):
        _param(doc, "EMAIL_EXACT")["parameter_id"] = pid
        assert any("UPPER_SNAKE_CASE" in e or "missing" in e for e in _errors(doc))

    @pytest.mark.parametrize("weight", [-0.1, 1.5, "0.3", None, float("inf"), True])
    def test_feature_weight_must_be_a_unit_number(self, doc, weight):
        _param(doc, "EMAIL_EXACT")["weight"] = weight
        assert any("weight must be a number in [0, 1]" in e for e in _errors(doc))

    @pytest.mark.parametrize("pid", ["ANCHOR_SHA256", "TIMEZONE_CERTAINTY"])
    def test_anchor_and_reliability_weight_must_be_null(self, doc, pid):
        _param(doc, pid)["weight"] = 0.2
        assert any("weight must be null" in e for e in _errors(doc))

    def test_contradiction_must_weaken(self, doc):
        _param(doc, "IDENTITY_CONFLICT")["direction"] = "SUPPORTS"
        assert any("must have direction WEAKENS" in e for e in _errors(doc))

    def test_feature_must_support(self, doc):
        _param(doc, "EMAIL_EXACT")["direction"] = "WEAKENS"
        assert any("must have direction SUPPORTS" in e for e in _errors(doc))

    def test_unknown_source_field_is_rejected(self, doc):
        _param(doc, "EMAIL_EXACT")["source_fields"] = ["actor.email", "made.up"]
        assert any("unknown field(s) ['made.up']" in e for e in _errors(doc))

    def test_unknown_extraction_method(self, doc):
        _param(doc, "EMAIL_EXACT")["extraction_method"] = {"method": "TELEPATHY"}
        assert any("extraction_method.method" in e for e in _errors(doc))

    def test_unknown_normalisation_kind(self, doc):
        _param(doc, "EMAIL_EXACT")["normalisation_rule"] = {"kind": "MAGIC"}
        assert any("normalisation_rule.kind" in e for e in _errors(doc))

    @pytest.mark.parametrize("rule", [{"kind": "LINEAR_DECAY"}, {"kind": "LINEAR_DECAY", "window_seconds": 0},
                                      {"kind": "UNIT_RESCALE"}, {"kind": "UNIT_RESCALE", "min_factor": 2},
                                      {"kind": "UNIT_FLOOR", "floor": 1.0}])
    def test_normalisation_options_validated(self, doc, rule):
        _param(doc, "TIME_DELTA")["normalisation_rule"] = rule
        assert _errors(doc)

    def test_anchor_requires_anchor_method_and_vice_versa(self, doc):
        _param(doc, "ANCHOR_SHA256")["extraction_method"] = {"method": "EXACT_MATCH"}
        _param(doc, "EMAIL_EXACT")["extraction_method"] = {"method": "ANCHOR_EXACT"}
        errs = _errors(doc)
        assert any("must use an ANCHOR_* extraction method" in e for e in errs)
        assert any("may only be used by ANCHOR parameters" in e for e in errs)

    def test_scoped_anchor_needs_known_scope_and_mode(self, doc):
        em = _param(doc, "ANCHOR_THREAD_ID")["extraction_method"]
        em["scope_fields"] = ["nope"]
        assert any("scope_fields" in e for e in _errors(doc))
        em["scope_fields"] = ["account.id"]
        em["scope_mode"] = "SOMETIMES"
        assert any("scope_mode" in e for e in _errors(doc))

    def test_conflict_check_needs_checks(self, doc):
        _param(doc, "INCONSISTENT_SOURCE_FACTS")["extraction_method"] = {"method": "CONFLICT_CHECK"}
        assert any("non-empty 'checks'" in e for e in _errors(doc))

    def test_conflict_check_unknown_fields(self, doc):
        _param(doc, "TIMESTAMP_CONFLICT")["extraction_method"]["checks"][0]["key_fields"] = ["nope"]
        assert any("unknown field(s)" in e for e in _errors(doc))

    def test_quality_map_must_be_unit_valued(self, doc):
        _param(doc, "SOURCE_TYPE")["extraction_method"]["map"]["log"] = 2
        assert any("FIELD_QUALITY_MAP needs a 'map'" in e for e in _errors(doc))

    def test_clock_uncertainty_needs_window(self, doc):
        _param(doc, "CLOCK_UNCERTAINTY")["extraction_method"].pop("window_seconds")
        assert any("CLOCK_UNCERTAINTY needs a positive window_seconds" in e for e in _errors(doc))

    # --- reliability, missing values, collisions ---------------------------------
    def test_feature_needs_reliability_rule(self, doc):
        _param(doc, "EMAIL_EXACT")["reliability_rule"] = None
        assert any("needs a reliability_rule" in e for e in _errors(doc))

    @pytest.mark.parametrize("pid", ["ANCHOR_SHA256", "SOURCE_TYPE", "IDENTITY_CONFLICT"])
    def test_non_feature_must_not_have_reliability_rule(self, doc, pid):
        _param(doc, pid)["reliability_rule"] = {"factors": [], "combine": "MIN", "floor": 0}
        assert any("reliability_rule must be null" in e for e in _errors(doc))

    def test_unknown_reliability_factor(self, doc):
        _param(doc, "EMAIL_EXACT")["reliability_rule"]["factors"] = ["NO_SUCH_FACTOR"]
        assert any("unknown parameter 'NO_SUCH_FACTOR'" in e for e in _errors(doc))

    def test_reliability_factor_must_be_a_reliability_factor(self, doc):
        _param(doc, "EMAIL_EXACT")["reliability_rule"]["factors"] = ["USERNAME_MATCH"]
        assert any("is not a RELIABILITY_FACTOR" in e for e in _errors(doc))

    def test_reliability_combine_and_floor(self, doc):
        rr = _param(doc, "EMAIL_EXACT")["reliability_rule"]
        rr["combine"] = "AVERAGE"
        rr["floor"] = 2
        errs = _errors(doc)
        assert any("combine" in e for e in errs) and any("floor" in e for e in errs)

    def test_missing_value_policy_must_be_known(self, doc):
        _param(doc, "EMAIL_EXACT")["missing_value_policy"] = {"policy": "GUESS"}
        assert any("missing_value_policy.policy" in e for e in _errors(doc))

    @pytest.mark.parametrize("policy", [{"policy": "EXPLICIT_PENALTY"}, {"policy": "EXPLICIT_PENALTY", "penalty": 0},
                                        {"policy": "EXPLICIT_PENALTY", "penalty": 1.5}])
    def test_explicit_penalty_needs_a_penalty(self, doc, policy):
        _param(doc, "EMAIL_EXACT")["missing_value_policy"] = policy
        assert any("EXPLICIT_PENALTY needs a penalty" in e for e in _errors(doc))

    def test_collision_rule_only_on_features(self, doc):
        _param(doc, "IDENTITY_CONFLICT")["collision_penalty_rule"] = {"kind": "HUB_COUNT", "counter": "ip"}
        assert any("only FEATURE parameters" in e for e in _errors(doc))

    def test_collision_rule_validated(self, doc):
        _param(doc, "SHARED_IP")["collision_penalty_rule"] = {"kind": "HUB_COUNT", "counter": "planet"}
        _param(doc, "FILENAME")["collision_penalty_rule"] = {"kind": "COMMON_VALUE", "list": "filenames",
                                                              "penalty_factor": 0}
        _param(doc, "PORT_MATCH")["collision_penalty_rule"] = {"kind": "COMMON_VALUE", "list": "nonexistent",
                                                                "penalty_factor": 0.5}
        errs = _errors(doc)
        assert any("HUB_COUNT counter" in e for e in errs)
        assert any("penalty_factor" in e for e in errs)
        assert any("COMMON_VALUE list" in e for e in errs)

    def test_common_value_list_must_be_defined_in_reference_data(self, doc):
        del doc["reference_data"]["common_values"]["filenames"]
        assert any("not defined in reference_data.common_values" in e for e in _errors(doc))

    # --- calibration / thresholds ---------------------------------------------------
    def test_calibrated_threshold_under_provisional_registry_is_rejected(self, doc):
        doc["thresholds"]["T_HIGH"]["status"] = "CALIBRATED"
        assert any("CALIBRATED but the registry calibration is PROVISIONAL" in e for e in _errors(doc))

    def test_calibrated_weight_under_provisional_registry_is_rejected(self, doc):
        _param(doc, "EMAIL_EXACT")["weight_status"] = "CALIBRATED"
        assert any("weight_status is CALIBRATED but the registry calibration is PROVISIONAL" in e
                   for e in _errors(doc))

    def test_calibrated_registry_must_cite_evaluation(self, doc):
        doc["calibration"] = {"status": "CALIBRATED"}
        for p in doc["parameters"]:
            p["weight_status"] = "CALIBRATED"
        for t in doc["thresholds"].values():
            t["status"] = "CALIBRATED"
        assert any("evaluation_ref" in e for e in _errors(doc))
        doc["calibration"]["evaluation_ref"] = "bench/results/example"
        assert _errors(doc) == []

    def test_unknown_calibration_status(self, doc):
        doc["calibration"]["status"] = "TRUSTED"
        assert any("calibration.status" in e for e in _errors(doc))

    @pytest.mark.parametrize("high,review", [(0.3, 0.6), (0.5, 0.5), (1.2, 0.3), (0.6, -0.1), (0.6, 0.0)])
    def test_threshold_ordering_and_range(self, doc, high, review):
        doc["thresholds"]["T_HIGH"]["value"] = high
        doc["thresholds"]["T_REVIEW"]["value"] = review
        assert any("threshold" in e.lower() for e in _errors(doc))

    def test_threshold_needs_numeric_value(self, doc):
        doc["thresholds"]["T_HIGH"]["value"] = "0.6"
        assert any("thresholds.T_HIGH needs a numeric 'value'" in e for e in _errors(doc))

    def test_score_model_clamp(self, doc):
        doc["score_model"]["clamp_min"] = 1.0
        doc["score_model"]["clamp_max"] = 0.0
        assert any("clamp_min < clamp_max" in e for e in _errors(doc))

    # --- candidate generation & reference data --------------------------------------
    def test_candidate_generation_validated(self, doc):
        cg = doc["candidate_generation"]
        cg["windows_seconds"] = {"staging": 10}
        cg["hub_thresholds"] = {"ip": 0, "moon": 3}
        cg["indexes"] = ["file_hash", "file_hash", "crystal_ball"]
        cg["max_bucket_size"] = 1
        errs = _errors(doc)
        assert any("'default' window" in e for e in errs)
        assert any("hub_thresholds.ip" in e for e in errs)
        assert any("unknown counter 'moon'" in e for e in errs)
        assert any("duplicates" in e for e in errs)
        assert any("unknown index" in e for e in errs)
        assert any("max_bucket_size" in e for e in errs)

    def test_reference_data_validated(self, doc):
        rd = doc["reference_data"]
        rd["ordered_action_pairs"] = [["only_one"]]
        rd["common_values"]["unknown_list"] = ["x"]
        rd["alias_groups"] = [{"group_id": "G", "members": ["solo"]}]
        errs = _errors(doc)
        assert any("ordered_action_pairs" in e for e in errs)
        assert any("unknown list" in e for e in errs)
        assert any("alias_groups" in e for e in errs)

    @pytest.mark.parametrize("field,value", [("effective_date", "24-11-2026"), ("effective_date", 20261124),
                                             ("change_reason", " "), ("schema_version", "9"),
                                             ("registry_version", "bad version"), ("config_version", "")])
    def test_top_level_metadata_validated(self, doc, field, value):
        doc[field] = value
        assert _errors(doc)

    # --- relation types and sources -------------------------------------------------
    @pytest.mark.parametrize("pattern", ["MAIL", "MAIL-MAIL-MAIL", "FOO-*", "NETWORK-MAIL", "mail-mail", ""])
    def test_invalid_relation_patterns(self, doc, pattern):
        # Pair kinds are alphabetical (MAIL-NETWORK, not NETWORK-MAIL).
        _param(doc, "EMAIL_EXACT")["relation_type"] = [pattern]
        assert any("relation_type" in e for e in _errors(doc))

    def test_invalid_applies_to_sources(self, doc):
        _param(doc, "EMAIL_EXACT")["applies_to_sources"] = ["fax"]
        assert any("applies_to_sources" in e for e in _errors(doc))

    def test_constructor_does_not_mutate_its_input(self, doc):
        before = copy.deepcopy(doc)
        R.Registry(doc)
        assert doc == before

    # --- fixture contract -----------------------------------------------------------
    @pytest.mark.parametrize("kind", ["positive", "negative"])
    def test_fixtures_required(self, doc, kind):
        del _param(doc, "EMAIL_EXACT")["fixtures"][kind]
        assert any("fixtures" in e for e in _errors(doc))

    def test_fixture_events_must_be_a_pair_the_parameter_covers(self, doc):
        # SENDER_RECIPIENT only applies to MAIL-MAIL pairs.
        fx = _param(doc, "SENDER_RECIPIENT")["fixtures"]["positive"]
        fx["events"][1] = {"source": "pcap", "timestamp": "2026-10-18T02:30:00Z"}
        errs = _errors(doc)
        assert any("relation_type does not cover" in e for e in errs)
        assert any("outside applies_to_sources" in e for e in errs)

    def test_fixture_expect_validated(self, doc):
        _param(doc, "EMAIL_EXACT")["fixtures"]["positive"]["expect"] = {"value": 3, "colour": "red"}
        _param(doc, "ANCHOR_SHA256")["fixtures"]["positive"]["expect"] = {"status": "EVALUATED"}
        _param(doc, "FILENAME")["fixtures"]["negative"]["expect"] = {}
        errs = _errors(doc)
        assert any("unknown key(s) ['colour']" in e for e in errs)
        assert any("expect.value must be a number" in e for e in errs)
        assert any("status must be one of ('ANCHORED'" in e for e in errs)
        assert any("expect must be a non-empty object" in e for e in errs)

    def test_anchor_fixture_must_declare_status(self, doc):
        _param(doc, "ANCHOR_SHA256")["fixtures"]["positive"]["expect"] = {"value": 1.0}
        assert any("needs a status for an ANCHOR" in e for e in _errors(doc))

    def test_fixture_events_need_source_and_timestamp(self, doc):
        _param(doc, "EMAIL_EXACT")["fixtures"]["positive"]["events"][0] = {"actor": "x"}
        errs = _errors(doc)
        assert any("known event source" in e for e in errs)
        assert any("needs a timestamp" in e for e in errs)


# ---------------------------------------------------------------------------
# Lookup, filtering and counts
# ---------------------------------------------------------------------------
class TestLookupAndCounts:
    def test_lookup(self, reg):
        p = reg.get("EMAIL_EXACT")
        assert p.parameter_id == "EMAIL_EXACT" and p.role == "FEATURE" and p.family == "IDENTITY"
        assert "EMAIL_EXACT" in reg and "NOPE" not in reg
        assert reg.find("NOPE") is None
        assert len(reg) == len(reg.parameters)
        with pytest.raises(R.UnknownParameterError):
            reg.get("NOPE")

    def test_registry_order_is_file_order(self, reg):
        file_ids = [p["parameter_id"] for p in json.loads((PACKAGE_DIR / "registry_v1.json").read_text())["parameters"]]
        assert [p.parameter_id for p in reg.parameters] == file_ids

    def test_disabled_parameters_are_excluded_from_enabled_counts_but_still_registered(self, reg):
        disabled = [p for p in reg.parameters if not p.enabled]
        assert [p.parameter_id for p in disabled] == ["USER_AGENT"]
        assert reg.count_enabled() == len(reg) - len(disabled)
        assert "USER_AGENT" not in {p.parameter_id for p in reg.filter()}
        assert "USER_AGENT" in {p.parameter_id for p in reg.filter(enabled_only=False)}
        assert reg.count_enabled(family="NETWORK") == len(reg.filter(family="NETWORK", enabled_only=True))
        assert reg.count_enabled(family="NETWORK") == len(reg.filter(family="NETWORK", enabled_only=False)) - 1

    def test_disabled_parameters_are_not_used_for_a_pair(self, reg):
        assert "USER_AGENT" not in {p.parameter_id for p in reg.for_pair("browser", "pcap")}

    def test_filter_by_relationship_class(self, reg):
        primary = reg.filter(relationship_class="PRIMARY")
        assert {p.role for p in primary} == {"ANCHOR"}
        secondary = reg.filter(relationship_class="SECONDARY")
        assert {p.role for p in secondary} == {"FEATURE", "CONTRADICTION", "RELIABILITY_FACTOR"}
        assert len(primary) + len(secondary) == reg.count_enabled()

    def test_filter_by_relation_type(self, reg):
        mail = {p.parameter_id for p in reg.filter(relation_type="MAIL-MAIL")}
        net = {p.parameter_id for p in reg.filter(relation_type="NETWORK-NETWORK")}
        cross = {p.parameter_id for p in reg.filter(relation_type="MAIL-NETWORK")}
        assert "ANCHOR_MESSAGE_ID" in mail and "ANCHOR_MESSAGE_ID" not in net | cross
        assert "ENDPOINT_PAIR" in net and "ENDPOINT_PAIR" not in mail | cross
        assert "SHARED_IP" in mail and "SHARED_IP" in net and "SHARED_IP" in cross
        assert "ANCHOR_SESSION_ID" not in cross
        assert len(mail) != len(net) != len(cross)

    def test_filter_by_source_type(self, reg):
        zeek = {p.parameter_id for p in reg.filter(source_type="zeek")}
        gmail = {p.parameter_id for p in reg.filter(source_type="gmail")}
        chat = {p.parameter_id for p in reg.filter(source_type="chat")}
        assert "ANCHOR_SESSION_ID" in zeek and "ANCHOR_SESSION_ID" not in gmail | chat
        assert "ANCHOR_MESSAGE_ID" in gmail and "ANCHOR_MESSAGE_ID" not in zeek | chat
        assert "TEXT_SIMILARITY" in chat and "TEXT_SIMILARITY" not in zeek | gmail
        assert {p.parameter_id for p in reg.filter(source_type="outlook")} == gmail

    def test_filter_by_family_and_role(self, reg):
        assert {p.family for p in reg.filter(family="IDENTITY")} == {"IDENTITY"}
        assert {p.role for p in reg.filter(role="CONTRADICTION")} == {"CONTRADICTION"}
        assert reg.count_enabled(role="ANCHOR", family="ARTIFACT") + reg.count_enabled(role="ANCHOR", family="NETWORK") \
            == reg.count_enabled(role="ANCHOR")

    def test_filters_combine(self, reg):
        got = reg.filter(relationship_class="SECONDARY", relation_type="MAIL-MAIL", source_type="gmail",
                         family="CONTENT", role="FEATURE")
        assert {p.parameter_id for p in got} == {"SUBJECT_SIMILARITY", "BODY_SIMILARITY", "URL_DOMAIN_SIMILARITY",
                                                 "ATTACHMENT_NAME_RELATION"}

    @pytest.mark.parametrize("kwargs", [{"relationship_class": "TERTIARY"}, {"relation_type": "FOO-BAR"},
                                        {"relation_type": "NETWORK-MAIL"}])
    def test_filter_rejects_unknown_criteria(self, reg, kwargs):
        with pytest.raises(ValueError):
            reg.filter(**kwargs)

    def test_for_pair_matches_pair_kind_and_sources(self, reg):
        ids = {p.parameter_id for p in reg.for_pair("gmail", "outlook")}
        assert {"ANCHOR_MESSAGE_ID", "SENDER_RECIPIENT", "SUBJECT_SIMILARITY"} <= ids
        assert "ENDPOINT_PAIR" not in ids
        assert {p.parameter_id for p in reg.for_pair("gmail", "zeek")}.isdisjoint({"ANCHOR_MESSAGE_ID", "ENDPOINT_PAIR"})
        # order independent
        assert [p.parameter_id for p in reg.for_pair("zeek", "pcap")] == [p.parameter_id for p in reg.for_pair("pcap", "zeek")]
        # restricted to a relationship class
        assert {p.role for p in reg.for_pair("zeek", "pcap", relationship_class="PRIMARY")} == {"ANCHOR"}

    def test_count_enabled_ignores_enabled_only_argument(self, reg):
        assert reg.count_enabled(enabled_only=False) == reg.count_enabled()

    def test_counts_are_not_a_fixed_number(self, doc):
        """Removing or disabling a parameter changes every derived count; no total is hard-coded."""
        base = R.Registry(doc)
        smaller = copy.deepcopy(doc)
        smaller["parameters"] = [p for p in smaller["parameters"] if p["parameter_id"] != "MIME_TYPE"]
        assert R.Registry(smaller).count_enabled() == base.count_enabled() - 1
        _param(smaller, "FILE_SIZE")["status"] = "DISABLED"
        assert R.Registry(smaller).count_enabled() == base.count_enabled() - 2
        assert R.Registry(smaller).describe()["counts"]["disabled"] == 2

    def test_parameter_applies_helpers(self, reg):
        p = reg.get("ANCHOR_SESSION_ID")
        assert p.applies_to_pair("zeek", "pcap") and not p.applies_to_pair("zeek", "gmail")
        assert p.applies_to_source("ZEEK") and not p.applies_to_source("gmail") and not p.applies_to_source(None)
        assert reg.get("EMAIL_EXACT").applies_to_source(None)  # "*" accepts anything

    def test_parameter_dict_is_a_copy(self, reg):
        d = reg.get("EMAIL_EXACT").to_dict()
        d["weight"] = 99
        assert reg.get("EMAIL_EXACT").weight == 0.30


# ---------------------------------------------------------------------------
# describe() / export
# ---------------------------------------------------------------------------
class TestDescribeAndExport:
    def test_describe_counts_equal_independently_recomputed_counts(self, reg):
        d = reg.describe()
        c = d["counts"]
        enabled = [p for p in reg.parameters if p.enabled]
        assert c["total_registered"] == len(reg.parameters)
        assert c["enabled"] == len(enabled)
        assert c["disabled"] == len(reg.parameters) - len(enabled)
        for key, attr in (("enabled_by_role", "role"), ("enabled_by_family", "family"),
                          ("enabled_by_relationship_class", "relationship_class")):
            expected: dict[str, int] = {}
            for p in enabled:
                expected[getattr(p, attr)] = expected.get(getattr(p, attr), 0) + 1
            assert c[key] == dict(sorted(expected.items()))
        for kind in V.all_pair_kinds():
            assert c["enabled_by_pair_kind"][kind] == sum(1 for p in enabled if p.applies_to_pair_kind(kind))
            for cls in V.RELATIONSHIP_CLASSES:
                assert c["enabled_by_relationship_class_and_pair_kind"][cls][kind] == sum(
                    1 for p in enabled if p.relationship_class == cls and p.applies_to_pair_kind(kind))
        for src in V.KNOWN_EVENT_SOURCES:
            assert c["enabled_by_source_type"][src] == sum(1 for p in enabled if p.applies_to_source(src))

    def test_describe_exposes_versions_hash_thresholds_and_provisional_status(self, reg):
        d = reg.describe(include_parameters=False)
        assert d["registry_version"] == reg.registry_version
        assert d["config_version"] == reg.config_version
        assert d["registry_hash"] == reg.registry_hash
        assert d["provisional"] is True
        assert "PROVISIONAL" in d["notice"]
        assert d["thresholds"]["T_HIGH"]["status"] == d["thresholds"]["T_REVIEW"]["status"] == "PROVISIONAL"
        assert "parameters" not in d
        full = reg.describe()
        assert len(full["parameters"]) == len(reg)
        assert json.loads(json.dumps(full)) == full  # JSON-serialisable

    def test_describe_is_a_copy(self, reg):
        d = reg.describe()
        d["thresholds"]["T_HIGH"]["value"] = 0.0
        assert reg.t_high == 0.60

    def test_export_round_trips(self, reg):
        again = R.Registry(reg.export())
        assert again.registry_hash == reg.registry_hash
        assert again.export() == reg.export()
        assert R.Registry(json.loads(reg.to_json())).registry_hash == reg.registry_hash

    def test_export_is_a_copy(self, reg):
        e = reg.export()
        e["parameters"].clear()
        e["thresholds"]["T_HIGH"]["value"] = 0.0
        assert len(reg) > 0 and reg.t_high == 0.60

    def test_threshold_accessors(self, reg):
        assert (reg.t_high, reg.t_review) == (0.60, 0.35)
        assert reg.t_review < reg.t_high


# ---------------------------------------------------------------------------
# Deterministic hash
# ---------------------------------------------------------------------------
class TestRegistryHash:
    def test_hash_is_sha256_hex_and_stable_across_loads(self):
        a, b = R.load_registry().registry_hash, R.load_registry("v1").registry_hash
        assert a == b and re.fullmatch(r"[0-9a-f]{64}", a)

    def test_hash_is_independent_of_key_order_and_whitespace(self, doc):
        reordered = json.loads(json.dumps(doc, sort_keys=True))
        reversed_params = copy.deepcopy(doc)
        reversed_params = {k: reversed_params[k] for k in reversed(list(reversed_params))}
        assert R.Registry(reordered).registry_hash == R.Registry(doc).registry_hash
        assert R.Registry(reversed_params).registry_hash == R.Registry(doc).registry_hash

    def test_hash_covers_parameter_order(self, doc):
        swapped = copy.deepcopy(doc)
        swapped["parameters"][0], swapped["parameters"][1] = swapped["parameters"][1], swapped["parameters"][0]
        assert R.Registry(swapped).registry_hash != R.Registry(doc).registry_hash

    @pytest.mark.parametrize("mutate", [
        lambda d: _param(d, "EMAIL_EXACT").__setitem__("weight", 0.31),
        lambda d: _param(d, "SHARED_IP").__setitem__("status", "DISABLED"),
        lambda d: _param(d, "USER_AGENT").__setitem__("status", "ENABLED"),  # a disabled parameter still counts
        lambda d: _param(d, "USER_AGENT").__setitem__("weight", 0.07),       # ...even while disabled
        lambda d: d["thresholds"]["T_HIGH"].__setitem__("value", 0.61),
        lambda d: d["candidate_generation"]["hub_thresholds"].__setitem__("ip", 4),
        lambda d: d["reference_data"]["common_values"]["domains"].append("example.net"),
        lambda d: d["reference_data"]["ordered_action_pairs"].append(["a", "b"]),
        lambda d: d.__setitem__("config_version", "corr-config-v2"),
        lambda d: d.__setitem__("change_reason", "different reason"),
        lambda d: _param(d, "EMAIL_EXACT").__setitem__("change_reason", "tuned"),
        lambda d: _param(d, "EMAIL_EXACT")["missing_value_policy"].__setitem__("policy", "ZERO_CONTRIBUTION"),
        lambda d: _param(d, "EMAIL_EXACT")["fixtures"]["positive"].__setitem__("label", "relabelled"),
    ])
    def test_hash_changes_when_anything_in_the_registry_changes(self, doc, mutate):
        before = R.Registry(doc).registry_hash
        mutate(doc)
        assert R.Registry(doc).registry_hash != before

    def test_hash_is_computed_from_the_whole_document_not_just_weights(self, doc):
        base = R.Registry(doc).registry_hash
        doc["calibration"]["note"] = doc["calibration"]["note"] + " (edited)"
        assert R.Registry(doc).registry_hash != base


# ---------------------------------------------------------------------------
# Shipped registry content
# ---------------------------------------------------------------------------
class TestShippedRegistry:
    def test_everything_is_labelled_provisional(self, reg):
        assert reg.is_provisional and reg.calibration_status == "PROVISIONAL"
        assert {p.weight_status for p in reg.parameters} == {"PROVISIONAL"}
        assert {t["status"] for t in reg.thresholds.values()} == {"PROVISIONAL"}

    def test_required_families_and_roles_are_present_and_enabled(self, reg):
        assert {p.family for p in reg.filter()} == set(V.FAMILIES)
        assert {p.role for p in reg.filter()} == set(V.ROLES)

    def test_every_capability_named_in_the_task_brief_has_a_parameter(self, reg):
        required = {
            "IDENTITY": {"ACCOUNT_EXACT", "EMAIL_EXACT", "ALIAS_MAPPED", "USERNAME_MATCH"},
            "ARTIFACT": {"MESSAGE_REF_OVERLAP", "ATTACHMENT_HASH", "FILE_HASH", "FILENAME", "MIME_TYPE", "FILE_SIZE"},
            "TEMPORAL": {"TIME_DELTA", "EVENT_ORDER", "WINDOW_OVERLAP", "TIMEZONE_CERTAINTY", "CLOCK_UNCERTAINTY"},
            "NETWORK": {"SHARED_IP", "ENDPOINT_PAIR", "PORT_MATCH", "PROTOCOL_MATCH", "DOMAIN_MATCH",
                        "DNS_RESOLUTION", "SESSION_ID", "USER_AGENT"},
            "CONTENT": {"SUBJECT_SIMILARITY", "BODY_SIMILARITY", "URL_DOMAIN_SIMILARITY",
                        "ATTACHMENT_NAME_RELATION", "TEXT_SIMILARITY"},
            "PROVENANCE": {"SOURCE_TYPE", "ACQUISITION_METHOD", "PARSER_CONFIDENCE", "TIMESTAMP_QUALITY",
                           "EVIDENCE_INTEGRITY"},
            "CONTRADICTION": {"IDENTITY_CONFLICT", "IMPOSSIBLE_ORDER", "TIMESTAMP_CONFLICT",
                              "INCONSISTENT_SOURCE_FACTS"},
        }
        by_family = {f: {p.parameter_id for p in reg.parameters if p.family == f} for f in required}
        for family, ids in required.items():
            assert ids <= by_family[family], (family, ids - by_family[family])
        anchors = {p.parameter_id for p in reg.parameters if p.role == "ANCHOR"}
        assert anchors == {"ANCHOR_SHA256", "ANCHOR_MESSAGE_ID", "ANCHOR_MESSAGE_REFERENCE", "ANCHOR_THREAD_ID",
                           "ANCHOR_SESSION_ID"}

    def test_all_three_missing_value_policies_are_in_use(self, reg):
        used = {p.missing_policy["policy"] for p in reg.parameters}
        assert used == set(V.MISSING_VALUE_POLICIES)

    def test_both_collision_kinds_are_in_use(self, reg):
        kinds = {p.collision_rule["kind"] for p in reg.parameters if p.collision_rule}
        assert kinds == set(V.COLLISION_KINDS)

    def test_only_features_have_weights_and_all_are_unit_valued(self, reg):
        for p in reg.parameters:
            if p.role in ("FEATURE", "CONTRADICTION"):
                assert 0.0 <= p.weight <= 1.0
            else:
                assert p.weight is None

    def test_provisional_threshold_sanity_targets(self, reg):
        """Design intent for the provisional weights (not an empirical claim).

        A weak signal on its own must never reach the review threshold; a validated-style hash match on
        its own is allowed to reach review but not the high threshold.
        """
        w = {p.parameter_id: p.weight for p in reg.parameters if p.role == "FEATURE"}
        for weak in ("SHARED_IP", "TIME_DELTA", "FILENAME", "PORT_MATCH", "MIME_TYPE", "FILE_SIZE", "PROTOCOL_MATCH"):
            assert w[weak] < reg.t_review, weak
        assert w["SHARED_IP"] + w["TIME_DELTA"] < reg.t_review          # IP + time alone: still not reviewable
        assert w["ACCOUNT_EXACT"] + w["TIME_DELTA"] >= reg.t_review     # account + compatible time: review band
        assert w["ACCOUNT_EXACT"] + w["TIME_DELTA"] < reg.t_high
        assert w["EMAIL_EXACT"] + w["TIME_DELTA"] + w["EVENT_ORDER"] + w["DOMAIN_MATCH"] >= reg.t_high
        for h in ("FILE_HASH", "ATTACHMENT_HASH"):
            assert reg.t_review <= w[h] < reg.t_high

    def test_consistency_with_existing_t5_constants(self, reg):
        cg = reg.candidate_generation
        assert cg["hub_thresholds"]["ip"] == t5.IP_HUB_THRESHOLD
        assert cg["hub_thresholds"]["device"] == t5.DEVICE_HUB_THRESHOLD
        assert cg["windows_seconds"]["default"] == intel_config.DEFAULT_CORRELATION_WINDOW.total_seconds()
        assert cg["windows_seconds"]["staging"] == intel_config.ARCHIVE_UPLOAD_WINDOW.total_seconds()
        assert reg.get("TIME_DELTA").normalisation["window_seconds"] == cg["windows_seconds"]["default"]
        assert reg.get("CLOCK_UNCERTAINTY").extraction["window_seconds"] == cg["windows_seconds"]["default"]

    def test_ordered_pairs_contain_t5_seed(self, reg):
        """T5's ORDERED_PAIRS is a function-local literal; read it from source so T5 stays untouched."""
        tree = ast.parse((Path(t5.__file__)).read_text(encoding="utf-8"))
        literal = next(ast.literal_eval(n.value) for n in ast.walk(tree)
                       if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "ORDERED_PAIRS" for t in n.targets))
        registry_pairs = {tuple(p) for p in reg.reference_data["ordered_action_pairs"]}
        assert literal <= registry_pairs
        assert registry_pairs - literal == {("dns_query", "network_connection")}

    def test_hash_and_integrity_vocabulary_matches_backend_constants(self, reg):
        """The integrity states come from backend/app/db/models.py (read as text: no SQLAlchemy needed)."""
        text = (Path(t5.__file__).resolve().parents[1] / "backend" / "app" / "db" / "models.py").read_text(encoding="utf-8")
        backend_states = set(re.findall(r'^VERIFY_\w+ = "(\w+)"', text, flags=re.M))
        backend_status = set(re.findall(r'^EVIDENCE_(?:QUARANTINED|REMOVED) = "(\w+)"', text, flags=re.M))
        em = reg.get("EVIDENCE_INTEGRITY").extraction
        assert backend_states == {"MATCH", "MISMATCH", "MISSING", "CUSTODY_BROKEN"}
        assert {"MISMATCH", "MISSING", "CUSTODY_BROKEN"} <= set(em["block_values"])
        assert backend_status <= set(em["block_values"])
        assert "MATCH" in em["map"] and not (set(em["map"]) & set(em["block_values"]))

    def test_the_only_disabled_parameter_has_a_documented_reason(self, reg):
        p = reg.get("USER_AGENT")
        assert not p.enabled and "no parser emits" in p.spec["change_reason"].lower()

    def test_every_vocabulary_field_is_used_by_some_parameter(self, reg):
        used: set[str] = set()
        for p in reg.parameters:
            used |= set(p.source_fields)
            em = p.extraction
            for check in em.get("checks", []):
                used |= set(check["key_fields"]) | set(check["fact_fields"])
            for pair in em.get("pairs", []):
                used |= set(pair)
            used |= set(em.get("scope_fields", []))
        assert V.FIELD_NAMES - used == set(), "dead vocabulary: remove or use these field names"
        assert used - V.FIELD_NAMES == set()

    def test_every_parameter_has_positive_and_negative_fixtures(self, reg):
        seen = {(p.parameter_id, kind) for p, kind, _ in R.iter_fixtures(reg)}
        assert len(seen) == 2 * len(reg)
        for p, kind, fx in R.iter_fixtures(reg):
            assert fx["label"] and fx["expect"] and len(fx["events"]) == 2, (p.parameter_id, kind)
        # positive and negative must differ in their expectation
        for p in reg.parameters:
            pos, neg = p.spec["fixtures"]["positive"], p.spec["fixtures"]["negative"]
            assert pos["expect"] != neg["expect"] or pos["events"] != neg["events"], p.parameter_id

    def test_fixtures_exist_for_disabled_parameters_too(self, reg):
        assert reg.get("USER_AGENT").spec["fixtures"]["positive"]["events"]

    def test_parameters_have_distinct_display_names_and_nonblank_documentation(self, reg):
        names = [p.spec["display_name"] for p in reg.parameters]
        assert len(set(names)) == len(names)
        for p in reg.parameters:
            assert len(p.spec["description"]) > 30
            assert p.spec["version"] and p.spec["effective_date"] and p.spec["change_reason"]

    def test_no_double_counting_between_hash_features(self, reg):
        """ATTACHMENT_HASH and FILE_HASH must not share a field pair."""
        def pairs(pid):
            return {tuple(x) for x in reg.get(pid).extraction["pairs"]}
        assert pairs("ATTACHMENT_HASH").isdisjoint(pairs("FILE_HASH"))

    def test_reliability_factors_are_not_additive_features(self, reg):
        factors = {p.parameter_id for p in reg.parameters if p.role == "RELIABILITY_FACTOR"}
        for p in reg.parameters:
            if p.role == "FEATURE":
                assert set(p.reliability_rule["factors"]) <= factors
                assert p.reliability_rule["factors"], p.parameter_id
        for f in factors:
            assert reg.get(f).weight is None and reg.get(f).reliability_rule is None

    def test_registry_file_is_ascii_and_lf_terminated(self):
        raw = (PACKAGE_DIR / "registry_v1.json").read_bytes()
        raw.decode("ascii")
        assert b"\r" not in raw and raw.endswith(b"\n")


# ---------------------------------------------------------------------------
# Vocabulary helpers
# ---------------------------------------------------------------------------
class TestVocabulary:
    def test_pair_kind_is_order_independent_and_alphabetical(self):
        assert V.pair_kind("zeek", "gmail") == V.pair_kind("gmail", "zeek") == "MAIL-NETWORK"
        assert V.pair_kind("gmail", "outlook") == "MAIL-MAIL"
        assert V.pair_kind("pst", "gmail") == "MAIL-MAIL"

    def test_unknown_and_missing_sources(self):
        assert V.category_of(None) == V.UNKNOWN_CATEGORY == "OTHER"
        assert V.category_of("fax") == "OTHER"
        assert V.pair_kind("fax", None) == "OTHER-OTHER"
        assert V.category_of("GMAIL") == "MAIL"

    def test_all_pair_kinds_are_derived_from_categories(self):
        n = len(V.SOURCE_CATEGORIES)
        assert len(V.all_pair_kinds()) == n * (n + 1) // 2
        assert len(set(V.all_pair_kinds())) == len(V.all_pair_kinds())

    def test_every_event_source_maps_to_a_category(self):
        assert set(V.KNOWN_EVENT_SOURCES) == set(V.SOURCE_CATEGORY)

    def test_event_sources_match_the_event_contract(self):
        schema = json.loads((Path(t5.__file__).resolve().parents[1] / "contracts" / "event.schema.json").read_text())
        assert tuple(schema["properties"]["source"]["enum"]) == V.KNOWN_EVENT_SOURCES

    @pytest.mark.parametrize("patterns,kind,expected", [
        (["ANY"], "MAIL-NETWORK", True),
        (["MAIL-NETWORK"], "MAIL-NETWORK", True),
        (["MAIL-*"], "MAIL-NETWORK", True),
        (["MAIL-*"], "CHAT-MAIL", True),
        (["MAIL-*"], "CHAT-NETWORK", False),
        (["NETWORK-NETWORK"], "MAIL-NETWORK", False),
        (["MAIL-MAIL", "NETWORK-NETWORK"], "NETWORK-NETWORK", True),
        ([], "MAIL-MAIL", False),
    ])
    def test_relation_type_matching(self, patterns, kind, expected):
        assert V.relation_type_matches(patterns, kind) is expected

    @pytest.mark.parametrize("pattern,ok", [("ANY", True), ("MAIL-*", True), ("MAIL-MAIL", True), ("MAIL-NETWORK", True),
                                            ("NETWORK-MAIL", False), ("FOO-*", False), ("MAIL", False), ("", False)])
    def test_valid_relation_pattern(self, pattern, ok):
        assert V.valid_relation_pattern(pattern) is ok

    def test_role_to_class_mapping_is_total(self):
        assert set(V.ROLE_TO_RELATIONSHIP_CLASS) == set(V.ROLES)
        assert set(V.ROLE_TO_RELATIONSHIP_CLASS.values()) == set(V.RELATIONSHIP_CLASSES)
