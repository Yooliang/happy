import { Client } from 'ldapts';
import { log, warn } from '@/utils/log';

interface LdapConfig {
    servers: string[];
    netbios: string;
    domain: string;
    baseDn: string;
}

function getConfig(): LdapConfig {
    return {
        servers: (process.env.LDAP_SERVERS || '192.168.1.230,192.168.1.231').split(',').map(s => s.trim()),
        netbios: process.env.LDAP_NETBIOS || 'GS-AD',
        domain: process.env.LDAP_DOMAIN || 'greenshepherd.com.tw',
        baseDn: process.env.LDAP_BASE_DN || 'DC=greenshepherd,DC=com,DC=tw',
    };
}

/**
 * Strip domain prefix from username (GS-AD\cwen0708 → cwen0708)
 */
export function cleanUsername(username: string): string {
    return username.includes('\\') ? username.split('\\').pop()! : username;
}

/**
 * Authenticate a user against AD via LDAP simple bind.
 * Tries each configured server in order (failover).
 */
export async function authenticate(username: string, password: string): Promise<{ success: boolean; error?: string }> {
    const config = getConfig();
    const name = cleanUsername(username);
    const bindDn = `${config.netbios}\\${name}`;

    for (const server of config.servers) {
        const client = new Client({ url: `ldap://${server}`, connectTimeout: 5000 });
        try {
            await client.bind(bindDn, password);
            await client.unbind();
            log({ module: 'ldap' }, `Auth success: ${name} via ${server}`);
            return { success: true };
        } catch (err: any) {
            const msg = err.message || String(err);
            // Only warn on connection errors; auth failures are expected
            if (msg.includes('connect') || msg.includes('timeout') || msg.includes('ECONNREFUSED')) {
                warn({ module: 'ldap' }, `Server ${server} unavailable: ${msg}`);
            } else {
                log({ module: 'ldap' }, `Auth failed for ${name} on ${server}: ${msg}`);
            }
            try { await client.unbind(); } catch { /* ignore */ }
        }
    }
    return { success: false, error: 'Invalid credentials' };
}
