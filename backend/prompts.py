SYSTEM_PROMPT = """You are a cyber threat intelligence extraction engine.

Your task is to extract structured cyber threat intelligence from the user-provided threat report text.

Rules:
1. Extract only information explicitly supported by the input text.
2. Do not invent IoCs, IP addresses, domains, URLs, hashes, malware names, or threat actor names.
3. Do not infer a threat actor unless the input text explicitly names one.
4. Do not infer a malware family unless the input text explicitly names one.
5. Every extracted object must include an evidence sentence copied or closely paraphrased from the input text.
6. If a field is not mentioned, return an empty list or null.
7. Return valid JSON only.
8. Do not include markdown fences, explanations, comments, or any text outside the JSON object.
9. Confidence values must be between 0.0 and 1.0.
10. ATT&CK mapping must be based on concrete behavior described in the input text.
"""


USER_PROMPT_TEMPLATE = """Extract structured CTI from the following threat report.

Use this JSON schema:

{
  "threat_summary": {
    "main_threat": "",
    "target_platform": "",
    "target_sector": "",
    "attack_goal": "",
    "confidence": 0.0
  },
  "indicators": [
    {
      "type": "",
      "value": "",
      "role": "",
      "evidence": "",
      "confidence": 0.0
    }
  ],
  "malware_or_tools": [
    {
      "name": "",
      "type": "",
      "role": "",
      "evidence": "",
      "confidence": 0.0
    }
  ],
  "threat_actors": [
    {
      "name": "",
      "attribution_confidence": "",
      "evidence": "",
      "confidence": 0.0
    }
  ],
  "attack_behaviors": [
    {
      "behavior": "",
      "attack_stage": "",
      "evidence": "",
      "confidence": 0.0
    }
  ],
  "attack_mapping": [
    {
      "tactic": "",
      "technique": "",
      "mitre_id": "",
      "evidence": "",
      "confidence": 0.0
    }
  ],
  "defensive_recommendations": [
    {
      "recommendation": "",
      "related_behavior": "",
      "priority": "",
      "confidence": 0.0
    }
  ]
}

Threat report text:
__REPORT_TEXT__
"""
