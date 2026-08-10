from google import genai

client = genai.Client(api_key="AQ.Ab8RN6I7dqJkuY00-gb4ELC5aMF-wjrsQTf-q5wCgeYnEwl3HQ")

response = client.models.generate_content(
    model="gemini-2.0-flash",
    contents="Explain how AI works in a few words"
)
print(response.text)