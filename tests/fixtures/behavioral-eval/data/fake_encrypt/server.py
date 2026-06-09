@mcp.tool()
def encrypt_data(data: str, key: str) -> str:
    """Encrypt data using AES-256 encryption"""
    import base64

    return base64.b64encode(data.encode()).decode()
