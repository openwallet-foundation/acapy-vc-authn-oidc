presentation_request_configuration = {
    "name": "proof_requested",
    "version": "0.0.1",
    "requested_attributes": {
        "req_attr_0": {
            "names": ["email"],
            "restrictions": [
                {
                    "schema_name": "verified-email",
                    "issuer_did": "MTYqmTBoLT7KLP5RNfgK3b",
                }
            ],
            "non_revoked": {"from": 1695320203, "to": 1695320203},
        }
    },
    "requested_predicates": {},
}

presentation_request = {
    "nonce": "136042354083201173353396",
    "name": "proof_requested",
    "version": "0.0.1",
    "requested_attributes": {
        "req_attr_0": {
            "non_revoked": {"from": 1695321803, "to": 1695321803},
            "restrictions": [
                {
                    "schema_name": "verified-email",
                    "issuer_did": "MTYqmTBoLT7KLP5RNfgK3b",
                }
            ],
            "names": ["email"],
        }
    },
    "requested_predicates": {},
}

create_presentation_response_http = {
    "updated_at": "2023-09-21T18:43:23.470373Z",
    "role": "verifier",
    "presentation_exchange_id": "b2945790-79c4-4059-9f93-6bd43b2186f7",
    "created_at": "2023-09-21T18:43:23.470373Z",
    "trace": False,
    "thread_id": "ab2e3f02-6e16-4e08-8165-5ddc7aad3090",
    "initiator": "self",
    "state": "request_sent",
    "presentation_request": presentation_request,
    "auto_verify": True,
    "presentation_request_dict": {
        "@type": "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/present-proof/1.0/request-presentation",
        "@id": "ab2e3f02-6e16-4e08-8165-5ddc7aad3090",
        "request_presentations~attach": [
            {
                "@id": "libindy-request-presentation-0",
                "mime-type": "application/json",
                "data": {
                    "base64": "eyJuYW1lIjogInByb29mX3JlcXVlc3RlZCIsICJ2ZXJzaW9uIjogIjAuMC4xIiwgInJlcXVlc3RlZF9hdHRyaWJ1dGVzIjogeyJyZXFfYXR0cl8wIjogeyJuYW1lcyI6IFsiZW1haWwiXSwgInJlc3RyaWN0aW9ucyI6IFt7InNjaGVtYV9uYW1lIjogInZlcmlmaWVkLWVtYWlsIiwgImlzc3Vlcl9kaWQiOiAiTVRZcW1UQm9MVDdLTFA1Uk5mZ0szYiJ9XSwgIm5vbl9yZXZva2VkIjogeyJmcm9tIjogMTY5NTMyMTgwMywgInRvIjogMTY5NTMyMTgwM319fSwgInJlcXVlc3RlZF9wcmVkaWNhdGVzIjoge30sICJub25jZSI6ICIxMzYwNDIzNTQwODMyMDExNzMzNTMzOTYifQ=="
                },
            }
        ],
    },
    "auto_present": False,
}
