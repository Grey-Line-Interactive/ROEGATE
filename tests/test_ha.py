"""Tests for High-Availability Clustering."""

from datetime import datetime, timedelta, timezone

from src.service.ha import ClusterNode, HACluster, NodeState


class TestNodeCreation:
    def test_node_initial_state(self) -> None:
        cluster = HACluster(node_id="node-a", host="10.0.0.1", port=19990)
        assert cluster.self_node.node_id == "node-a"
        assert cluster.self_node.host == "10.0.0.1"
        assert cluster.self_node.port == 19990
        assert cluster.self_node.state == NodeState.CANDIDATE
        assert cluster.self_node.is_healthy is True
        assert cluster.self_node.last_heartbeat != ""

    def test_node_created_with_peers(self) -> None:
        cluster = HACluster(
            node_id="node-a",
            host="10.0.0.1",
            port=19990,
            peers=[("10.0.0.2", 19990), ("10.0.0.3", 19990)],
        )
        assert len(cluster.peers) == 2
        assert "10.0.0.2:19990" in cluster.peers
        assert "10.0.0.3:19990" in cluster.peers


class TestPeerManagement:
    def test_register_peer(self) -> None:
        cluster = HACluster(node_id="node-a", host="10.0.0.1", port=19990)
        peer = cluster.register_peer("10.0.0.2", 19990)
        assert peer.node_id == "10.0.0.2:19990"
        assert peer.host == "10.0.0.2"
        assert peer.state == NodeState.CANDIDATE
        assert "10.0.0.2:19990" in cluster.peers

    def test_remove_peer(self) -> None:
        cluster = HACluster(node_id="node-a", host="10.0.0.1", port=19990)
        cluster.register_peer("10.0.0.2", 19990)
        cluster.remove_peer("10.0.0.2:19990")
        assert "10.0.0.2:19990" not in cluster.peers

    def test_remove_nonexistent_peer_is_noop(self) -> None:
        cluster = HACluster(node_id="node-a", host="10.0.0.1", port=19990)
        cluster.remove_peer("nonexistent")  # should not raise


class TestLeaderElection:
    def test_leader_election_lowest_id_wins(self) -> None:
        cluster = HACluster(node_id="node-b", host="10.0.0.2", port=19990)
        cluster.register_peer("10.0.0.1", 19990)
        # peer id "10.0.0.1:19990" < "node-b"
        leader_id = cluster.elect_leader()
        assert leader_id == "10.0.0.1:19990"
        assert cluster.self_node.state == NodeState.FOLLOWER
        assert cluster.peers["10.0.0.1:19990"].state == NodeState.LEADER

    def test_leader_election_self_wins_when_lowest(self) -> None:
        # node_id "0-self" sorts before peer id "10.0.0.2:19990"
        cluster = HACluster(node_id="0-self", host="10.0.0.1", port=19990)
        cluster.register_peer("10.0.0.2", 19990)
        leader_id = cluster.elect_leader()
        assert leader_id == "0-self"
        assert cluster.is_leader() is True

    def test_unhealthy_node_excluded_from_election(self) -> None:
        cluster = HACluster(node_id="node-b", host="10.0.0.2", port=19990)
        peer = cluster.register_peer("10.0.0.1", 19990)
        peer.is_healthy = False  # mark peer unhealthy
        leader_id = cluster.elect_leader()
        assert leader_id == "node-b"
        assert cluster.is_leader() is True

    def test_no_healthy_nodes(self) -> None:
        cluster = HACluster(node_id="node-a", host="10.0.0.1", port=19990)
        cluster.self_node.is_healthy = False
        leader_id = cluster.elect_leader()
        assert leader_id == "node-a"
        assert cluster.self_node.state == NodeState.OFFLINE


class TestHealthMonitoring:
    def test_heartbeat_returns_correct_status(self) -> None:
        cluster = HACluster(node_id="node-a", host="10.0.0.1", port=19990)
        cluster.register_peer("10.0.0.2", 19990)
        hb = cluster.heartbeat()
        assert hb["node_id"] == "node-a"
        assert hb["is_healthy"] is True
        assert hb["peer_count"] == 1
        assert "last_heartbeat" in hb

    def test_check_peers_marks_stale_unhealthy(self) -> None:
        cluster = HACluster(node_id="node-a", host="10.0.0.1", port=19990)
        peer = cluster.register_peer("10.0.0.2", 19990)
        # Set heartbeat to 60 seconds ago
        stale = datetime.now(timezone.utc) - timedelta(seconds=60)
        peer.last_heartbeat = stale.isoformat()
        cluster.check_peers()
        assert peer.is_healthy is False
        assert peer.state == NodeState.OFFLINE

    def test_check_peers_keeps_fresh_healthy(self) -> None:
        cluster = HACluster(node_id="node-a", host="10.0.0.1", port=19990)
        peer = cluster.register_peer("10.0.0.2", 19990)
        # Heartbeat is fresh (just created)
        cluster.check_peers()
        assert peer.is_healthy is True


class TestClusterStatus:
    def test_get_cluster_status(self) -> None:
        cluster = HACluster(node_id="node-a", host="10.0.0.1", port=19990)
        cluster.register_peer("10.0.0.2", 19990)
        cluster.elect_leader()
        status = cluster.get_cluster_status()
        assert status["self"]["node_id"] == "node-a"
        assert status["total_nodes"] == 2
        assert status["healthy_nodes"] == 2
        assert status["leader"] is not None
        assert "10.0.0.2:19990" in status["peers"]

    def test_get_leader_none_before_election(self) -> None:
        cluster = HACluster(node_id="node-a", host="10.0.0.1", port=19990)
        assert cluster.get_leader() is None


class TestStateSync:
    def test_sync_state_round_trip(self) -> None:
        leader = HACluster(node_id="node-a", host="10.0.0.1", port=19990)
        follower = HACluster(node_id="node-b", host="10.0.0.2", port=19990)

        state = {
            "halted_sessions": ["sess-1", "sess-2"],
            "active_evaluations": 42,
        }
        leader.sync_state(state)
        exported = leader.get_sync_state()

        follower.sync_state(exported)
        assert follower.get_sync_state() == state

    def test_sync_state_overwrites_previous(self) -> None:
        cluster = HACluster(node_id="node-a", host="10.0.0.1", port=19990)
        cluster.sync_state({"key": "old"})
        cluster.sync_state({"key": "new"})
        assert cluster.get_sync_state() == {"key": "new"}
