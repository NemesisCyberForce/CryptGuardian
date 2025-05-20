def analyze_request_with_ai(payload: dict, model: str = "gpt-4") -> dict:
    # Preprocessing
    prompt = f"""
    Bitte analysiere folgenden sicherheitskritischen Request auf Anomalien:
    {payload}
    
    Hinweise auf:
    - Manipulation
    - Replay-Attacken
    - auffällige Nonce-Verwendung
    - Zeitstempel-Inkonsistenz
    """
    # Beispiel für OpenAI
    from openai import OpenAI
    response = OpenAI().chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content
