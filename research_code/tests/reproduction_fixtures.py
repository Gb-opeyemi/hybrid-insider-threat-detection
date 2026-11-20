"""Synthetic indexer response fixtures. No private captures or network access."""

def page(hits, total=2):
    return {'_scroll_id': 'synthetic-context', 'timed_out': False,
        '_shards': {'total': 1, 'failed': 0}, 'hits': {'total': {'value': total, 'relation': 'eq'}, 'hits': hits}}

def mapping():
    return {'wazuh-archives-synthetic': {'mappings': {'properties': {
        'timestamp': {'type': 'date'}, 'data': {'properties': {'win': {'properties': {'system': {
            'properties': {'systemTime': {'type': 'date'}, 'channel': {'type': 'keyword'}}}}}}}}}}}
