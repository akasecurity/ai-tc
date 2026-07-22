"""Customer event forwarding for the settlement worker."""

import requests


def track(payload):
    """Verb-first client API: the method is the call's first argument."""
    resp = requests.request('POST', 'https://api.segment.io/v1/track', json=payload)
    resp.raise_for_status()
    return resp.json()
