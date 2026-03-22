"""
High-Availability Clustering for ROE Gate

Provides leader election, health monitoring, and state synchronization
for running multiple Gate Service instances behind a load balancer.

Architecture:
- Multiple Gate instances share the same ROE spec and signing key
- Leader election determines which instance handles writes (halt/resume)
- Health checks enable load balancer failover
- State sync propagates halt/resume across instances
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class NodeState(Enum):
    LEADER = "leader"
    FOLLOWER = "follower"
    CANDIDATE = "candidate"
    OFFLINE = "offline"


@dataclass
class ClusterNode:
    node_id: str
    host: str
    port: int
    state: NodeState = NodeState.CANDIDATE
    last_heartbeat: str = ""
    is_healthy: bool = True

    def __post_init__(self) -> None:
        if not self.last_heartbeat:
            self.last_heartbeat = datetime.now(timezone.utc).isoformat()


class HACluster:
    """Manages a cluster of ROE Gate nodes with leader election and state sync."""

    def __init__(
        self,
        node_id: str,
        host: str,
        port: int,
        peers: list[tuple[str, int]] | None = None,
    ) -> None:
        self.self_node = ClusterNode(
            node_id=node_id,
            host=host,
            port=port,
            state=NodeState.CANDIDATE,
        )
        self.peers: dict[str, ClusterNode] = {}
        self._sync_state_data: dict = {}

        if peers:
            for peer_host, peer_port in peers:
                self.register_peer(peer_host, peer_port)

    # ------------------------------------------------------------------
    # Peer management
    # ------------------------------------------------------------------

    def register_peer(self, host: str, port: int) -> ClusterNode:
        """Register a peer node in the cluster."""
        peer_id = f"{host}:{port}"
        node = ClusterNode(
            node_id=peer_id,
            host=host,
            port=port,
            state=NodeState.CANDIDATE,
        )
        self.peers[peer_id] = node
        return node

    def remove_peer(self, node_id: str) -> None:
        """Remove a peer from the cluster."""
        self.peers.pop(node_id, None)

    # ------------------------------------------------------------------
    # Leader election
    # ------------------------------------------------------------------

    def elect_leader(self) -> str:
        """Simple leader election: lowest node_id among healthy nodes wins."""
        candidates: list[ClusterNode] = []

        if self.self_node.is_healthy:
            candidates.append(self.self_node)

        for peer in self.peers.values():
            if peer.is_healthy:
                candidates.append(peer)

        if not candidates:
            self.self_node.state = NodeState.OFFLINE
            return self.self_node.node_id

        candidates.sort(key=lambda n: n.node_id)
        leader = candidates[0]

        # Update states
        for node in candidates:
            if node.node_id == leader.node_id:
                node.state = NodeState.LEADER
            else:
                node.state = NodeState.FOLLOWER

        return leader.node_id

    def is_leader(self) -> bool:
        """Check if this node is currently the leader."""
        return self.self_node.state == NodeState.LEADER

    def get_leader(self) -> ClusterNode | None:
        """Return the current leader node, or None if no leader."""
        if self.self_node.state == NodeState.LEADER:
            return self.self_node
        for peer in self.peers.values():
            if peer.state == NodeState.LEADER:
                return peer
        return None

    # ------------------------------------------------------------------
    # Health monitoring
    # ------------------------------------------------------------------

    def heartbeat(self) -> dict:
        """Return health status for this node."""
        now = datetime.now(timezone.utc).isoformat()
        self.self_node.last_heartbeat = now
        return {
            "node_id": self.self_node.node_id,
            "state": self.self_node.state.value,
            "host": self.self_node.host,
            "port": self.self_node.port,
            "last_heartbeat": now,
            "is_healthy": self.self_node.is_healthy,
            "peer_count": len(self.peers),
        }

    def check_peers(self) -> None:
        """Mark peers as unhealthy if their heartbeat is stale (>30s)."""
        now = datetime.now(timezone.utc)
        for peer in self.peers.values():
            try:
                last = datetime.fromisoformat(peer.last_heartbeat)
                if (now - last).total_seconds() > 30:
                    peer.is_healthy = False
                    if peer.state != NodeState.OFFLINE:
                        peer.state = NodeState.OFFLINE
            except (ValueError, TypeError):
                peer.is_healthy = False

    # ------------------------------------------------------------------
    # State synchronization
    # ------------------------------------------------------------------

    def sync_state(self, state_data: dict) -> None:
        """Receive state from leader (halted_sessions, etc.)."""
        self._sync_state_data = dict(state_data)

    def get_sync_state(self) -> dict:
        """Export state for syncing to followers."""
        return dict(self._sync_state_data)

    # ------------------------------------------------------------------
    # Cluster overview
    # ------------------------------------------------------------------

    def get_cluster_status(self) -> dict:
        """Return full cluster overview."""
        leader = self.get_leader()
        return {
            "self": {
                "node_id": self.self_node.node_id,
                "host": self.self_node.host,
                "port": self.self_node.port,
                "state": self.self_node.state.value,
                "is_healthy": self.self_node.is_healthy,
            },
            "peers": {
                nid: {
                    "host": node.host,
                    "port": node.port,
                    "state": node.state.value,
                    "is_healthy": node.is_healthy,
                    "last_heartbeat": node.last_heartbeat,
                }
                for nid, node in self.peers.items()
            },
            "leader": leader.node_id if leader else None,
            "total_nodes": 1 + len(self.peers),
            "healthy_nodes": (
                (1 if self.self_node.is_healthy else 0)
                + sum(1 for p in self.peers.values() if p.is_healthy)
            ),
        }
