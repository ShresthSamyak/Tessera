from tessera.classification import (
    Reversibility,
    classify_tool,
    operator_profile,
)


def test_read_only_tool_is_safe():
    p = classify_tool("search_documents", {"properties": {"query": {}}})
    assert p.blast_radius.reversibility is Reversibility.READ_ONLY
    assert not p.blast_radius.exfiltration_capable
    assert not p.is_dangerous


def test_send_email_is_exfil_and_irreversible():
    p = classify_tool(
        "send_email",
        {"properties": {"to": {}, "subject": {}, "body": {}}},
    )
    assert p.blast_radius.exfiltration_capable  # 'send' verb + 'to' param
    assert p.blast_radius.reversibility is Reversibility.IRREVERSIBLE
    assert p.is_dangerous


def test_fetch_url_is_exfil_capable():
    p = classify_tool("fetch_url", {"properties": {"url": {}}})
    assert p.blast_radius.exfiltration_capable
    assert p.is_dangerous


def test_destination_param_alone_flags_exfil():
    # Name gives no exfil verb, but a free-text 'webhook' destination does.
    p = classify_tool("post_update", {"properties": {"webhook": {}, "text": {}}})
    assert p.blast_radius.exfiltration_capable


def test_delete_is_irreversible():
    p = classify_tool("delete_file", {"properties": {"path": {}}})
    assert p.blast_radius.reversibility is Reversibility.IRREVERSIBLE
    assert p.is_dangerous


def test_read_from_recipient_param_is_not_exfil():
    # The regression fix: a 'channel' (recipient) param on a READ tool must NOT
    # be flagged exfil-capable — it's a read selector, not a send target.
    for name in ("read_channel_messages", "get_users_in_channel"):
        p = classify_tool(name, {"properties": {"channel": {}}})
        assert not p.blast_radius.exfiltration_capable, name
        assert not p.is_dangerous, name


def test_send_to_recipient_param_is_exfil():
    p = classify_tool("send_channel_message", {"properties": {"channel": {}, "body": {}}})
    assert p.blast_radius.exfiltration_capable  # 'send' verb + recipient param


def test_outbound_url_param_is_exfil_even_on_get():
    # Fetching an arbitrary URL leaks via the URL itself, regardless of verb.
    p = classify_tool("get_webpage", {"properties": {"url": {}}})
    assert p.blast_radius.exfiltration_capable
    assert p.is_dangerous


def test_granting_access_is_exfil_flavored():
    p = classify_tool("invite_user_to_slack", {"properties": {"email": {}}})
    assert p.blast_radius.exfiltration_capable  # 'invite' exposes data to a new party
    assert p.is_dangerous


def test_reversible_write_is_not_dangerous():
    p = classify_tool("add_label", {"properties": {"id": {}, "label": {}}})
    assert p.blast_radius.reversibility is Reversibility.REVERSIBLE
    assert not p.blast_radius.exfiltration_capable
    assert not p.is_dangerous


def test_unknown_tool_defaults_cautious_not_readonly():
    p = classify_tool("frobnicate", {"properties": {"x": {}}})
    assert p.blast_radius.reversibility is Reversibility.REVERSIBLE
    # cautious middle, never silently READ_ONLY
    assert p.blast_radius.reversibility is not Reversibility.READ_ONLY


def test_camelcase_and_description_signal():
    # read-ish name, but description reveals it sends data outward
    p = classify_tool("processItem", description="Sends the item to a remote URL")
    assert p.blast_radius.exfiltration_capable


def test_operator_override_marks_source():
    p = operator_profile(
        "internal_lookup",
        reversibility=Reversibility.READ_ONLY,
        exfiltration_capable=False,
    )
    assert p.source == "operator"
    assert not p.is_dangerous
