from pydantic.config import JsonDict

ex_ver_config: JsonDict = {
    "ver_config_id": "test-request-config",
    "include_v1_attributes": False,
    "generate_consistent_identifier": False,
    "subject_identifier": "first_name",
    "proof_request": {
        "name": "Basic Proof",
        "version": "1.0",
        "requested_attributes": [
            {"names": ["first_name", "last_name"], "restrictions": []},
        ],
        "requested_predicates": [],
    },
}
