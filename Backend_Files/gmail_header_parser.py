def parse_headers(headers):

    parsed = {}

    for header in headers:

        parsed[
            header["name"]
        ] = header["value"]

    return parsed