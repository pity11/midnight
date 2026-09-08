from midnight.graph.router import route


def test_forensics_has_a_dedicated_specialist_node():
    assert route({"challenge_type": "forensics"}) == "forensics_specialist"
