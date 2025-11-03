# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

# pylint: disable=duplicate-code,missing-function-docstring
"""Unit tests for security logging enhancements."""

import unittest.mock as mock
from collections import defaultdict

import ops
import pytest
import token_distributor
from charms.k8s.v0.k8sd_api_manager import InvalidResponseError, K8sdConnectionError
from literals import CLUSTER_RELATION


def test_token_grant_security_logging(caplog):
    """Test that token grant emits security log."""
    api_manager_mock = mock.MagicMock(spec=token_distributor.K8sdAPIManager)
    manager = token_distributor.ClusterTokenManager(api_manager_mock())
    charm = mock.MagicMock(spec=ops.CharmBase)()
    unit = mock.MagicMock(spec=ops.Unit)()
    unit.name = "k8s/0"
    secret = mock.MagicMock(spec=ops.Secret)()
    secret.id = "secret-id-123"
    relation = mock.MagicMock()
    relation.name = "cluster"
    relation.data = defaultdict(dict)

    caplog.set_level("INFO")

    manager.grant(relation, charm, unit, secret)

    # Verify security log entry
    assert "SECURITY: Granted cluster token [secret_id=secret-id-123, target_unit=k8s/0, relation=cluster]" in caplog.text


def test_token_revoke_security_logging(caplog):
    """Test that token revoke emits security log."""
    api_manager_mock = mock.MagicMock(spec=token_distributor.K8sdAPIManager)
    manager = token_distributor.ClusterTokenManager(api_manager_mock())
    charm = mock.MagicMock(spec=ops.CharmBase)()
    unit = mock.MagicMock(spec=ops.Unit)()
    unit.name = "k8s/0"
    relation = mock.MagicMock()
    relation.name = "cluster"
    relation.data = defaultdict(dict)
    secret_key = token_distributor.CLUSTER_SECRET_ID.format(unit.name)
    relation.data[charm.app][secret_key] = "secret-id-456"

    secret = mock.MagicMock(spec=ops.Secret)()
    charm.model.get_secret.return_value = secret

    caplog.set_level("INFO")

    manager.revoke(relation, charm, unit)

    # Verify security log entry
    assert "SECURITY: Revoked cluster token [secret_id=secret-id-456, unit=k8s/0, relation=cluster]" in caplog.text
    secret.remove_all_revisions.assert_called_once_with()


def test_cluster_token_create_security_logging(caplog):
    """Test that cluster token creation emits security log."""
    api_manager_mock = mock.MagicMock(spec=token_distributor.K8sdAPIManager)
    api_manager = api_manager_mock()
    api_manager.create_join_token.return_value = mock.MagicMock()

    manager = token_distributor.ClusterTokenManager(api_manager)

    caplog.set_level("INFO")

    manager.create("test-node", token_distributor.ClusterTokenType.WORKER)

    # Verify security log entry
    assert "SECURITY: Created cluster join token [node=test-node, token_type=worker]" in caplog.text


def test_cluster_token_create_control_plane_security_logging(caplog):
    """Test that control plane token creation emits security log."""
    api_manager_mock = mock.MagicMock(spec=token_distributor.K8sdAPIManager)
    api_manager = api_manager_mock()
    api_manager.create_join_token.return_value = mock.MagicMock()

    manager = token_distributor.ClusterTokenManager(api_manager)

    caplog.set_level("INFO")

    manager.create("test-node", token_distributor.ClusterTokenType.CONTROL_PLANE)

    # Verify security log entry
    assert "SECURITY: Created cluster join token [node=test-node, token_type=control-plane]" in caplog.text


def test_cos_token_create_security_logging(caplog):
    """Test that COS token creation emits security log."""
    api_manager_mock = mock.MagicMock(spec=token_distributor.K8sdAPIManager)
    api_manager = api_manager_mock()
    api_manager.request_auth_token.return_value = mock.MagicMock()

    manager = token_distributor.CosTokenManager(api_manager)

    caplog.set_level("INFO")

    manager.create("test-node", token_distributor.ClusterTokenType.NONE)

    # Verify security log entry
    assert "SECURITY: Created cos token [node=test-node, username=system:cos:test-node, groups=system:cos]" in caplog.text


def test_node_removal_security_logging(caplog):
    """Test that node removal emits security logs."""
    api_manager_mock = mock.MagicMock(spec=token_distributor.K8sdAPIManager)
    api_manager = api_manager_mock()

    manager = token_distributor.ClusterTokenManager(api_manager)

    caplog.set_level("INFO")

    manager.remove("test-node", None, False)

    # Verify security log entries
    assert "SECURITY: Node removal initiated [node=test-node, force=False, strategy=cluster]" in caplog.text
    assert "SECURITY: Node removal completed [node=test-node, strategy=cluster]" in caplog.text


def test_node_removal_failure_security_logging(caplog):
    """Test that node removal failure emits security log."""
    api_manager_mock = mock.MagicMock(spec=token_distributor.K8sdAPIManager)
    api_manager = api_manager_mock()
    api_manager.remove_node.side_effect = K8sdConnectionError("Connection failed")

    manager = token_distributor.ClusterTokenManager(api_manager)

    caplog.set_level("ERROR")

    with pytest.raises(K8sdConnectionError):
        manager.remove("test-node", None, False)

    # Verify security log entry for failure
    assert "SECURITY: Node removal failed [node=test-node, error=Connection failed, strategy=cluster]" in caplog.text


def test_cos_auth_token_revocation_security_logging(caplog):
    """Test that COS auth token revocation emits security logs."""
    api_manager_mock = mock.MagicMock(spec=token_distributor.K8sdAPIManager)
    api_manager = api_manager_mock()

    manager = token_distributor.CosTokenManager(api_manager)

    secret = mock.MagicMock(spec=ops.Secret)()
    secret.get_content.return_value = {"revision": "0", "token": "test-token"}

    caplog.set_level("INFO")

    manager.remove("test-node", secret, False)

    # Verify security log entries
    assert "SECURITY: Auth token revocation initiated [node=test-node, strategy=cos]" in caplog.text
    assert "SECURITY: Auth token revoked [node=test-node, strategy=cos]" in caplog.text


def test_cos_auth_token_revocation_failure_security_logging(caplog):
    """Test that COS auth token revocation failure emits security log."""
    api_manager_mock = mock.MagicMock(spec=token_distributor.K8sdAPIManager)
    api_manager = api_manager_mock()
    api_manager.revoke_auth_token.side_effect = InvalidResponseError("Invalid token", 400)

    manager = token_distributor.CosTokenManager(api_manager)

    secret = mock.MagicMock(spec=ops.Secret)()
    secret.get_content.return_value = {"revision": "0", "token": "test-token"}

    caplog.set_level("ERROR")

    with pytest.raises(InvalidResponseError):
        manager.remove("test-node", secret, False)

    # Verify security log entry for failure
    assert "SECURITY: Auth token revocation failed [node=test-node, error=" in caplog.text
    assert "strategy=cos]" in caplog.text


def test_token_consumption_success_security_logging(harness, caplog):
    """Test that successful token consumption emits security log."""
    harness.disable_hooks()
    collector = token_distributor.TokenCollector(harness.charm, "my-node")

    relation_id = harness.add_relation("cluster", "remote", unit_data={"cluster-name": "test-cluster"})
    relation = harness.charm.model.get_relation(CLUSTER_RELATION)

    # Set up a secret
    secret_key = token_distributor.CLUSTER_SECRET_ID.format(harness.charm.unit.name)
    secret = harness.charm.model.app.add_secret({"revision": "0", "token": "test-token"})
    harness.update_relation_data(relation_id, "remote", {secret_key: secret.id})

    caplog.set_level("INFO")

    # Use the token
    with collector.recover_token(relation) as token:
        assert token == "test-token"

    # Verify security log entry
    assert "SECURITY: Token consumed for node join [node=my-node, token_revision=0, cluster=test-cluster, relation=cluster]" in caplog.text


def test_token_consumption_failure_security_logging(harness, caplog):
    """Test that failed token consumption emits security log."""
    harness.disable_hooks()
    collector = token_distributor.TokenCollector(harness.charm, "my-node")

    relation_id = harness.add_relation("cluster", "remote")
    relation = harness.charm.model.get_relation(CLUSTER_RELATION)

    # Set up a secret
    secret_key = token_distributor.CLUSTER_SECRET_ID.format(harness.charm.unit.name)
    secret = harness.charm.model.app.add_secret({"revision": "0", "token": "test-token"})
    harness.update_relation_data(relation_id, "remote", {secret_key: secret.id})

    caplog.set_level("ERROR")

    # Use the token and raise an exception
    try:
        with collector.recover_token(relation):
            raise RuntimeError("Join failed")
    except RuntimeError:
        pass

    # Verify security log entry
    assert "SECURITY: Token consumption failed [node=my-node, token_revision=0, relation=cluster, error=Join failed]" in caplog.text


def test_token_failure_detected_security_logging(caplog):
    """Test that token failure detection emits security log."""
    # This test verifies the logging in allocate_tokens when a token failure is detected
    # We'll need to set up the distributor with mocked components

    api_manager_mock = mock.MagicMock(spec=token_distributor.K8sdAPIManager)
    charm = mock.MagicMock()
    charm.app = mock.MagicMock()
    charm.unit = mock.MagicMock()
    charm.unit.name = "k8s/0"
    charm.model = mock.MagicMock()
    charm.get_cluster_name.return_value = "test-cluster"

    distributor = token_distributor.TokenDistributor(charm, "test-node", api_manager_mock())

    relation = mock.MagicMock()
    relation.name = "cluster"
    relation.app = charm.app
    relation.units = set()
    relation.data = defaultdict(dict)

    unit = mock.MagicMock()
    unit.name = "k8s/1"
    relation.units.add(unit)

    # Set up unit data to simulate a token request
    relation.data[unit][token_distributor.CLUSTER_NODE_NAME] = "remote-node"

    # Set up a secret
    secret = mock.MagicMock(spec=ops.Secret)()
    secret.id = "secret-id-789"
    secret.get_info.return_value = mock.MagicMock(revision=1)
    secret.get_content.return_value = {"revision": "1", "token": "test-token"}
    charm.model.get_secret.return_value = secret

    # Set up a token failure
    failure = token_distributor.TokenFailure(revision=1, error="Connection timeout")
    relation.data[unit][token_distributor.CLUSTER_TOKEN_FAILURE] = failure.model_dump_json()

    caplog.set_level("WARNING")

    # This should detect the failure and log it
    distributor.allocate_tokens(
        relation,
        token_distributor.TokenStrategy.CLUSTER,
        token_distributor.ClusterTokenType.WORKER,
    )

    # Verify security log entry
    assert "SECURITY: Token failure detected [node=remote-node, unit=k8s/1, relation=cluster, strategy=cluster, token_revision=1, error=Connection timeout]" in caplog.text
