def turnstile_validation(request, turnstile_secret, url, ):
    import requests

    # Validate Turnstile's response
    turnstile_response = request.POST.get('cf-turnstile-response')
    if not turnstile_response:
        print(
            "Turnstile response is missing.",
            "\n--------------------------------\n"
        )
        return False

    # Send to Turnstile
    print(
        "Turnstile Verify URL:",
        url,
        "\n--------------------------------\n"
    )
    data = {
        "secret": turnstile_secret,
        "response": turnstile_response
    }
    response = requests.post(url, data=data)
    result = response.json()
    print(
        "Turnstile API Response:",
        result,
        "\n--------------------------------\n"
    )

    if result.get("success"):
        # Turnstile validated successfully
        return True
    else:
        # Fails with Turnstile
        error_message = "Failed Turnstile verification."
        error_codes = result.get("error-codes", [])
        if error_codes:
            error_message += f" Errors: {', '.join(error_codes)}"
        print(
            error_message,
            "\n--------------------------------\n"
        )
        return False
