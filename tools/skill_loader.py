"""
Skill Loader
Implements progressive disclosure for agent skills.
L1: Loads skill name + trigger description at startup
L2: Loads full SKILL.md body only when skill is triggered
"""

import os

SKILLS_DIR = "skills"

SKILL_TO_TOOL_MAP = {
    "email-analysis": "analyze_email_text",
    "url-scanning": "scan_email_urls",
    "domain-reputation": "check_sender_domain",
    "verdict-generation": "generate_verdict"
}


def load_skill_metadata(skill_name: str) -> dict:
    skill_path = os.path.join(SKILLS_DIR, skill_name, "SKILL.md")
    if not os.path.exists(skill_path):
        return None
    with open(skill_path, "r") as f:
        content = f.read()
    lines = content.split("\n")
    name = ""
    trigger = ""
    for i, line in enumerate(lines):
        if line.startswith("# "):
            name = line.replace("# ", "").strip()
        if line.strip() == "## Trigger":
            if i + 1 < len(lines):
                trigger = lines[i + 1].strip()
    return {
        "skill_name": skill_name,
        "name": name,
        "trigger": trigger,
        "tool_name": SKILL_TO_TOOL_MAP.get(skill_name, skill_name)
    }


def load_skill_body(skill_name: str) -> str:
    skill_path = os.path.join(SKILLS_DIR, skill_name, "SKILL.md")
    if not os.path.exists(skill_path):
        return ""
    with open(skill_path, "r") as f:
        return f.read()


def load_all_skills_metadata() -> list:
    skills = []
    if not os.path.exists(SKILLS_DIR):
        return skills
    for skill_name in os.listdir(SKILLS_DIR):
        skill_path = os.path.join(SKILLS_DIR, skill_name)
        if os.path.isdir(skill_path):
            metadata = load_skill_metadata(skill_name)
            if metadata:
                skills.append(metadata)
    return skills


def build_tools_from_skills() -> list:
    skills = load_all_skills_metadata()
    tools = []
    for skill in skills:
        tool_name = skill["tool_name"]
        if tool_name == "analyze_email_text":
            tools.append({
                "type": "function",
                "function": {
                    "name": tool_name,
                    "description": skill["trigger"],
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "sender": {"type": "string"},
                            "subject": {"type": "string"},
                            "body": {"type": "string"}
                        },
                        "required": ["sender", "subject", "body"]
                    }
                }
            })
        elif tool_name == "scan_email_urls":
            tools.append({
                "type": "function",
                "function": {
                    "name": tool_name,
                    "description": skill["trigger"],
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "urls": {
                                "type": "array",
                                "items": {"type": "string"}
                            }
                        },
                        "required": ["urls"]
                    }
                }
            })
        elif tool_name == "check_sender_domain":
            tools.append({
                "type": "function",
                "function": {
                    "name": tool_name,
                    "description": skill["trigger"],
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "sender_email": {"type": "string"}
                        },
                        "required": ["sender_email"]
                    }
                }
            })
        elif tool_name == "generate_verdict":
            tools.append({
                "type": "function",
                "function": {
                    "name": tool_name,
                    "description": skill["trigger"],
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "findings": {
                                "type": "array",
                                "items": {"type": "string"}
                            },
                            "risk_score": {"type": "integer"}
                        },
                        "required": ["findings", "risk_score"]
                    }
                }
            })
    return tools


def get_skill_context_for_tool(tool_name: str) -> str:
    reverse_map = {v: k for k, v in SKILL_TO_TOOL_MAP.items()}
    skill_name = reverse_map.get(tool_name)
    if skill_name:
        return load_skill_body(skill_name)
    return ""