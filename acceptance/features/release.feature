Feature: Golden Container Image

    Scenario: Red Hat collection
        Given a sample policy input "golden-container"
        And a policy config:
            """
            {
                "sources": [
                    {
                        "policy": [
                            "$GITROOT/policy/lib",
                            "$GITROOT/policy/release"
                        ],
                        "data": [
                            "$GITROOT/example/data"
                        ],
                        "config": {
                            "include": [
                                "@redhat"
                            ],
                            "exclude": [
                                "cve.deprecated_cve_result_name",
                                "source_image"
                            ]
                        }
                    }
                ]
            }
            """
        When input is validated
        Then there should be no violations in the result
        Then there should be no warnings in the result
