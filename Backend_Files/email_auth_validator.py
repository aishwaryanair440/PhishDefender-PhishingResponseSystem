def validate_email_auth(headers):

    auth_results = headers.get(
        "Authentication-Results",
        ""
    )

    return {

        "spf_pass":
            "spf=pass"
            in auth_results.lower(),

        "dkim_pass":
            "dkim=pass"
            in auth_results.lower(),

        "dmarc_pass":
            "dmarc=pass"
            in auth_results.lower()

    }