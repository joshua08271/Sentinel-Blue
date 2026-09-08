import copy
import unittest
from unittest.mock import patch

from sentinel_blue.collectors import _windows_topology


def snapshot():
    return {
        'Schema': 1,
        'Errors': {},
        'Routes': [
            {'DestinationPrefix': '192.0.2.0/24', 'NextHop': '0.0.0.0', 'InterfaceAlias': 'Ethernet', 'RouteMetric': 5},
            {'DestinationPrefix': '2001:db8::/64', 'NextHop': '::', 'InterfaceAlias': 'Ethernet', 'RouteMetric': 6},
        ],
        'Neighbors': [{'IPAddress': '192.0.2.10', 'LinkLayerAddress': '00-11-22-33-44-55', 'InterfaceAlias': 'Ethernet', 'State': 'Reachable'}],
        'Listeners': [{'LocalAddress': '::', 'LocalPort': 443, 'OwningProcess': 42}],
    }


class WindowsTopologyBatchTests(unittest.TestCase):
    def test_batch_preserves_dual_stack_routes_neighbors_and_listener_ownership(self):
        errors = []
        with patch('sentinel_blue.collectors._windows_json', return_value=[snapshot()]) as query:
            routes, neighbors, listeners = _windows_topology(errors)
        self.assertFalse(errors)
        self.assertEqual([row.destination for row in routes], ['192.0.2.0/24', '2001:db8::/64'])
        self.assertEqual([row.metric for row in routes], [5, 6])
        self.assertEqual(neighbors[0].hardware_address, '00-11-22-33-44-55')
        self.assertEqual((listeners[0].address, listeners[0].port, listeners[0].process), ('::', 443, '42'))
        self.assertEqual(query.call_count, 1)

    def test_failed_section_cannot_look_complete_but_retains_other_observations(self):
        state = snapshot()
        state['Errors']['Routes'] = 'route provider unavailable'
        errors = []
        with patch('sentinel_blue.collectors._windows_json', return_value=[state]):
            routes, neighbors, listeners = _windows_topology(errors)
        self.assertFalse(routes, 'partial rows from the failed section must not be trusted')
        self.assertEqual(len(neighbors), 1)
        self.assertEqual(len(listeners), 1)
        self.assertTrue(any('route provider unavailable' in error for error in errors))

    def test_missing_or_malformed_sections_report_incomplete_collection(self):
        variants = []
        for key in ('Routes', 'Neighbors', 'Listeners', 'Errors'):
            state = snapshot()
            del state[key]
            variants.append(state)
        for key, value in (('Routes', None), ('Neighbors', [None]), ('Errors', []), ('Schema', 2)):
            state = copy.deepcopy(snapshot())
            state[key] = value
            variants.append(state)
        for state in variants:
            with self.subTest(state=state):
                errors = []
                with patch('sentinel_blue.collectors._windows_json', return_value=[state]):
                    _windows_topology(errors)
                self.assertTrue(errors)

    def test_exhausted_batch_deadline_does_not_launch_more_queries(self):
        errors = []
        with patch('sentinel_blue.collectors._windows_json', side_effect=RuntimeError('query deadline exhausted')) as query:
            self.assertEqual(_windows_topology(errors), ([], [], []))
        self.assertEqual(query.call_count, 1)
        self.assertTrue(errors)


if __name__ == '__main__':
    unittest.main()
