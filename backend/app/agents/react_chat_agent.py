"""
react_chat_agent.py — ReAct security agent for the AWS chat flow.

Builds a LangGraph ReAct agent that can call any of the 6 AWS security tools
(IAM, S3, EBS, CloudTrail, VPC, EC2) to answer free-form security questions.

The agent decides which tools to call and in what order — it can call multiple
tools in sequence to answer cross-domain questions.
"""

from __future__ import annotations

from typing import Any

from langchain_anthropic import ChatAnthropic
from langgraph.prebuilt import create_react_agent

from backend.app.agents.security_tools import build_security_tools

_SYSTEM_PROMPT = """You are an expert AWS cloud security analyst.

You have access to security scanning tools that query the user's AWS account directly via boto3.
Use them to answer the user's question with real data from their account.

Guidelines:
- Call the relevant tool(s) to get real findings before answering.
- If the question spans multiple domains (e.g. EC2 AND security groups), call both tools.
- Be concise and practical: state what was found, the risk, and the remediation.
- Use the CIS benchmark control numbers when relevant (e.g. CIS 1.14, CIS 5.2).
- If a tool returns no findings for a domain, say so explicitly — it's good news.
- Answer in the same language the user writes in.

Account context: {account_context}
"""


def build_react_agent(
    role_arn: str = "",
    region: str = "us-east-1",
    account_id: str = "",
) -> Any:
    """
    Build a ReAct agent with the 6 AWS security tools pre-bound to the account context.

    Args:
        role_arn:   IAM role to assume before scanning. Empty = ambient credentials.
        region:     AWS region for region-scoped tools. Default: us-east-1.
        account_id: AWS account ID shown in the system prompt for context.

    Returns:
        Compiled LangGraph ReAct agent ready for ainvoke().
    """
    llm = ChatAnthropic(model="claude-sonnet-4-6", temperature=0)
    tools = build_security_tools(role_arn=role_arn, region=region)

    account_context = f"Account: {account_id or 'unknown'}"
    if role_arn:
        account_context += f" | Role ARN: {role_arn}"
    account_context += f" | Region: {region}"

    system_prompt = _SYSTEM_PROMPT.format(account_context=account_context)

    return create_react_agent(llm, tools, prompt=system_prompt)


async def ask_react_agent(agent: Any, question: str) -> str:
    """
    Invoke the ReAct agent with a security question and return the final answer.

    Args:
        agent:    Compiled ReAct agent from build_react_agent().
        question: The user's security question.

    Returns:
        The agent's final text response.
    """
    from langchain_core.messages import HumanMessage

    result = await agent.ainvoke({"messages": [HumanMessage(content=question)]})
    messages = result.get("messages", [])
    if messages:
        return messages[-1].content
    return "No se pudo obtener una respuesta del agente."
