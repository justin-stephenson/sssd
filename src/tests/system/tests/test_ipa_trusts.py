"""
IPA Trusts.

:requirement: IDM-SSSD-REQ: Testing SSSD in IPA Provider
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericADProvider
from sssd_test_framework.roles.ipa import IPA
from sssd_test_framework.topology import KnownTopology, KnownTopologyGroup


@pytest.mark.importance("low")
@pytest.mark.ticket(jira="RHEL-3925", gh=6942)
@pytest.mark.topology(KnownTopologyGroup.IPATrustAD)
def test_ipa_trusts__lookup_group_without_sid(ipa: IPA, trusted: GenericADProvider):
    """
    :title: Subdomain stays online if IPA group is missing SID
    :description: This test is to check a bug that made SSSD go offline when an expected attribute was missing.
        This happens during applying overrides on cached group during initgroups of trusted user. If the group
        does not have SID (it's GID is outside the sidgen range), SSSD goes offline.
    :setup:
        1. Create IPA external group "external-group" and add AD user "Administrator" as a member
        2. Create IPA posix group "posix-group" and add "external-group" as a member
        3. Clear SSSD cache and logs on IPA server
        4. Restart SSSD on IPA server
    :steps:
        1. Lookup AD administrator user
        2. Clear user cache
        3. Lookup AD administrator user
        4. Check logs using sssctl for domain status
    :expectedresults:
        1. User is found and is a member of 'posix-group'
        2. User cache expired
        3. User is found and is a member of 'posix-group'
        4. No messages indicating AD went offline
    :customerscenario: True
    """
    username = trusted.fqn("administrator")
    external = ipa.group("external-group").add(external=True).add_member(username)
    ipa.group("posix-group").add(gid=5001).add_member(external)

    ipa.sssd.clear(db=True, memcache=True, logs=True)
    ipa.sssd.restart()

    # Cache trusted user
    result = ipa.tools.id(username)
    assert result is not None, "User not found!"
    assert result.memberof("posix-group"), "User is not a member of 'posix-group'!"

    # Expire the user and resolve it again, this will trigger the affected code path
    ipa.sssctl.cache_expire(user=username)
    result = ipa.tools.id(username)
    assert result is not None, "User not found!"
    assert result.memberof("posix-group"), "User is not a member of 'posix-group'!"

    # Check that SSSD did not go offline
    status = ipa.sssctl.domain_status(trusted.domain, online=True)
    assert "online status: offline" not in status.stdout.lower(), "AD domain went offline!"
    assert "online status: online" in status.stdout.lower(), "AD domain was not online!"


@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopologyGroup.AnyIPATrust)
def test_ipa_trusts__ipa_master_lookup_trusted_user(ipa: IPA, trusted: IPA):
    """
    :title: Basic IPA-IPA Trust lookup on IPA server
    :setup:
        1. Restart SSSD and clear cache on IPA server
    :steps:
        1. Resolve trusted domain admin user
    :expectedresults:
        1. User is resolved
    :customerscenario: True
    """
    ipa.sssd.clear(db=True, memcache=True, logs=True)
    ipa.sssd.restart()

    # Resolve user
    username = trusted.admin_fqn

    id_user = ipa.tools.id(username)
    assert id_user is not None
    assert id_user.user.name == username


@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.IPATrustIPA)
def test_ipa_trusts__lookup_trusted_user(client: Client, ipa: IPA, trusted: IPA):
    """
    :title: Basic IPA-IPA Trust lookup on IPA client
    :setup:
        1. Restart SSSD and clear cache on IPA client
    :steps:
        1. Resolve trusted admin user
        2. Resolve group "admins@trusteddomain"
    :expectedresults:
        1. User is resolved
        2. Group is resolved
    :customerscenario: True
    """
    client.sssd.clear(db=True, memcache=True, logs=True)
    client.sssd.restart()

    # Resolve user
    username = trusted.admin_fqn

    id_user = client.tools.id(username)
    assert id_user is not None
    assert id_user.user.name == username

    # Resolve group
    groupname = trusted.fqn("admins")

    getent_group = client.tools.getent.group(groupname)
    assert getent_group is not None
    assert getent_group.name == groupname
