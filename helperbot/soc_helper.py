import json

def load_playbooks():
    with open("playbooks.json", "r") as f:
        return json.load(f)

def soc_helper(query):
    playbooks = load_playbooks()
    for pb in playbooks:
        if pb["keyword"].lower() in query.lower():
            print(f"MITRE Technique: {pb['technique']}")
            print(f" Relevant Logs: {', '.join(pb['logs'])}")
            print(" Investigation Steps:")
            for i, step in enumerate(pb["steps"], 1):
                print(f"  {i}. {step}")
            return
    print("X No match found. Consider updating your playbooks.json.")

if __name__ == "__main__":
    query = input("Enter alert/log description: ")
    soc_helper(query)
