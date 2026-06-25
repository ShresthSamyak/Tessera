from tessera.labels import Origin, TrustLevel, combine, combine_iter


def test_trust_ordering():
    assert TrustLevel.UNTRUSTED < TrustLevel.UNVERIFIED < TrustLevel.INTERNAL < TrustLevel.TRUSTED


def test_is_untrusted_covers_unverified():
    assert TrustLevel.UNTRUSTED.is_untrusted
    assert TrustLevel.UNVERIFIED.is_untrusted
    assert not TrustLevel.INTERNAL.is_untrusted
    assert not TrustLevel.TRUSTED.is_untrusted


def test_is_trusted():
    assert TrustLevel.INTERNAL.is_trusted
    assert TrustLevel.TRUSTED.is_trusted
    assert not TrustLevel.UNTRUSTED.is_trusted


def test_combine_takes_minimum():
    assert combine(TrustLevel.TRUSTED, TrustLevel.UNTRUSTED) is TrustLevel.UNTRUSTED
    assert combine(TrustLevel.TRUSTED, TrustLevel.INTERNAL) is TrustLevel.INTERNAL


def test_combine_identity_is_top():
    assert combine() is TrustLevel.TRUSTED


def test_combine_iter():
    assert combine_iter([TrustLevel.INTERNAL, TrustLevel.UNVERIFIED]) is TrustLevel.UNVERIFIED


def test_origin_default_levels():
    assert Origin.USER_QUERY.default_level is TrustLevel.TRUSTED
    assert Origin.WEB_CONTENT.default_level is TrustLevel.UNTRUSTED
    assert Origin.INBOUND_MESSAGE.default_level is TrustLevel.UNTRUSTED
    assert Origin.VETTED_SYSTEM.default_level is TrustLevel.INTERNAL
    assert Origin.UNKNOWN.default_level is TrustLevel.UNVERIFIED
