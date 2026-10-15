import sys
import json
import requests

def audit_mcp(target_base):
    print(f"[*] Auditing MCP server interface: {target_base}")
    tools_endpoint = f"{target_base.rstrip('/')}/tools/list"
    
    headers = {"Content-Type": "application/json"}
    try:
        response = requests.post(tools_endpoint, json={}, headers=headers, timeout=5)
        if response.status_code != 200:
            # Fallback to GET if JSON-RPC/REST variant
            response = requests.get(target_base, headers=headers, timeout=5)
            
        data = response.json()
        print("[+] Successfully connected to MCP service interface.")
        
        tools = data.get("tools", data.get("result", {}).get("tools", []))
        print(f"[*] Discovered {len(tools)} registered tools.")
        
        for tool in tools:
            name = tool.get("name", "unknown")
            desc = tool.get("description", "")
            print(f"\n    - Tool: {name}")
            print(f"      Description: {desc[:100]}...")
            
            # Check for suspicious description injections or dangerous parameters
            if any(kw in desc.lower() for kw in ["system:", "ignore previous", "override", "execute"]):
                print(f"      [!] WARNING: Potential tool-description prompt injection vector identified in '{name}'!")
                
            schema = tool.get("inputSchema", {})
            properties = schema.get("properties", {})
            for prop_name, prop_val in properties.items():
                prop_desc = prop_val.get("description", "").lower()
                if any(term in prop_desc for term in ["path", "cmd", "command", "file", "eval", "exec"]):
                    print(f"      [?] Parameter '{prop_name}' handles high-risk context ({prop_val.get('type')}). Test for command/path injection.")

    except Exception as e:
        print(f"[-] Failed to enumerate MCP tools or parse endpoint: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python mcp_scanner.py <MCP_SERVER_URL>")
        sys.exit(1)
    audit_mcp(sys.argv[1])