import unittest

from sentinel_blue.topology import build_topology


class TopologyTests(unittest.TestCase):
    def test_filters_observations_outside_scope(self):
        graph = build_topology(
            [
                {
                    "agent_id": "a1",
                    "hostname": "host",
                    "neighbors": [
                        {"address": "198.51.100.2", "interface": "eth0"},
                        {"address": "192.0.2.4", "interface": "eth0"},
                    ],
                    "routes": [{"gateway": "198.51.100.1", "interface": "eth0"}],
                }
            ],
            ["198.51.100.0/24"],
        )
        labels = {node["label"] for node in graph["nodes"]}
        self.assertIn("198.51.100.2", labels)
        self.assertNotIn("192.0.2.4", labels)

    def test_neighbor_address_resolves_to_managed_host(self):
        graph = build_topology(
            [
                {
                    "agent_id": "a1",
                    "hostname": "first",
                    "interfaces": [{"name": "eth0", "addresses": ["198.51.100.1/24"]}],
                    "neighbors": [{"address": "198.51.100.2", "interface": "eth0"}],
                    "routes": [],
                },
                {
                    "agent_id": "a2",
                    "hostname": "second",
                    "interfaces": [{"name": "eth0", "addresses": ["198.51.100.2/24"]}],
                    "neighbors": [],
                    "routes": [],
                },
            ],
            ["198.51.100.0/24"],
        )
        self.assertIn(
            {"source": "a1", "target": "a2", "interface": "eth0"},
            graph["links"],
        )
        second = next(node for node in graph["nodes"] if node["id"] == "a2")
        self.assertEqual(second["addresses"], ["198.51.100.2"])


if __name__ == "__main__":
    unittest.main()
