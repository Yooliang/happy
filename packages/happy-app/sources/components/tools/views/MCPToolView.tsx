/**
 * Converts snake_case string to PascalCase with spaces
 * Example: "create_issue" -> "Create Issue"
 */
function snakeToPascalWithSpaces(str: string): string {
    return str
        .split('_')
        .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
        .join(' ');
}

/** Chinese display names for known MCP tools */
const MCP_TOOL_LABELS: Record<string, string> = {
    'nas__search_files': '搜尋 NAS 檔案',
    'nas__list_directory': '列出 NAS 目錄',
    'nas__read_file': '讀取 NAS 檔案',
    'nas__get_file_info': '取得 NAS 檔案資訊',
    'nas__list_shares': '列出 NAS 共用資料夾',
    'nas__create_sharing_link': '建立 NAS 分享連結',
    'happy__change_title': '變更對話標題',
};

/**
 * Formats MCP tool name to display title
 * Example: "mcp__nas__list_directory" -> "列出 NAS 目錄"
 */
export function formatMCPTitle(toolName: string): string {
    // Remove "mcp__" prefix
    const withoutPrefix = toolName.replace(/^mcp__/, '');

    // Check for known Chinese label
    if (MCP_TOOL_LABELS[withoutPrefix]) {
        return MCP_TOOL_LABELS[withoutPrefix];
    }

    // Split into parts by "__"
    const parts = withoutPrefix.split('__');

    if (parts.length >= 2) {
        const serverName = snakeToPascalWithSpaces(parts[0]);
        const toolNamePart = snakeToPascalWithSpaces(parts.slice(1).join('_'));
        return `${serverName} ${toolNamePart}`;
    }

    // Fallback if format doesn't match expected pattern
    return snakeToPascalWithSpaces(withoutPrefix);
}