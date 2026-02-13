import * as React from 'react';
import { View, Text, FlatList, Pressable, ActivityIndicator, Platform } from 'react-native';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { useAllMachines, useIsDataReady, useAllSessions, storage } from '@/sync/storage';
import { machineSpawnNewSession, sessionDelete } from '@/sync/ops';
import { sync } from '@/sync/sync';
import { isMachineOnline } from '@/utils/machineUtils';
import { getSessionName, useSessionStatus, getSessionSubtitle } from '@/utils/sessionUtils';
import { StyleSheet, useUnistyles } from 'react-native-unistyles';
import { Typography } from '@/constants/Typography';
import { useAuth } from '@/auth/AuthContext';
import { Session } from '@/sync/storageTypes';
import { StatusDot } from '@/components/StatusDot';
import { CompanyHeader } from '@/components/CompanyHeader';
import { Ionicons } from '@expo/vector-icons';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { kvGet, kvSet } from '@/sync/apiKv';
import { encodeBase64, decodeBase64 } from '@/encryption/base64';

/**
 * AD User session page.
 * Shows a simplified session list for AD users.
 * - Header with username + logout button
 * - Session list (tap to enter)
 * - "+" button to create new session (auto-picks first machine)
 * - No TabBar, no sidebar, no settings/inbox navigation
 */
export default React.memo(function AdUserPage() {
    const { username } = useLocalSearchParams<{ username: string }>();
    const router = useRouter();
    const isDataReady = useIsDataReady();
    const machines = useAllMachines();
    const allSessions = useAllSessions();
    const { theme } = useUnistyles();
    const auth = useAuth();
    const insets = useSafeAreaInsets();

    const [isSpawning, setIsSpawning] = React.useState(false);
    const [error, setError] = React.useState<string | null>(null);

    // Session ownership via KV API
    const [ownedSessionIds, setOwnedSessionIds] = React.useState<Set<string>>(new Set());
    const [kvVersion, setKvVersion] = React.useState<number>(-1); // -1 = new key
    const [ownershipLoaded, setOwnershipLoaded] = React.useState(false);

    const kvKey = `ad-sessions.${username}`;

    const loadOwnedSessions = React.useCallback(async () => {
        const credentials = sync.getCredentials();
        if (!credentials) return;
        try {
            const item = await kvGet(credentials, kvKey);
            if (item) {
                const json = new TextDecoder().decode(decodeBase64(item.value));
                const ids: string[] = JSON.parse(json);
                setOwnedSessionIds(new Set(ids));
                setKvVersion(item.version);
            }
        } catch (e) {
            console.error('Failed to load owned sessions:', e);
        } finally {
            setOwnershipLoaded(true);
        }
    }, [kvKey]);

    const addOwnedSession = React.useCallback(async (sessionId: string) => {
        const credentials = sync.getCredentials();
        if (!credentials) return;
        const newIds = [...ownedSessionIds, sessionId];
        const encoded = encodeBase64(new TextEncoder().encode(JSON.stringify(newIds)));
        try {
            const newVersion = await kvSet(credentials, kvKey, encoded, kvVersion);
            setOwnedSessionIds(new Set(newIds));
            setKvVersion(newVersion);
        } catch (e) {
            console.error('Failed to save owned session:', e);
            await loadOwnedSessions();
        }
    }, [ownedSessionIds, kvVersion, kvKey, loadOwnedSessions]);

    const removeOwnedSession = React.useCallback(async (sessionId: string) => {
        const credentials = sync.getCredentials();
        if (!credentials) return;
        const newIds = [...ownedSessionIds].filter(id => id !== sessionId);
        const encoded = encodeBase64(new TextEncoder().encode(JSON.stringify(newIds)));
        try {
            const newVersion = await kvSet(credentials, kvKey, encoded, kvVersion);
            setOwnedSessionIds(new Set(newIds));
            setKvVersion(newVersion);
        } catch (e) {
            console.error('Failed to update owned sessions:', e);
            await loadOwnedSessions();
        }
    }, [ownedSessionIds, kvVersion, kvKey, loadOwnedSessions]);

    const handleDeleteSession = React.useCallback(async (sessionId: string) => {
        if (!confirm('Delete this session?')) return;
        try {
            const result = await sessionDelete(sessionId);
            if (result.success) {
                storage.getState().deleteSession(sessionId);
                await removeOwnedSession(sessionId);
            } else {
                setError(result.message || 'Failed to delete');
            }
        } catch (e: any) {
            setError(e?.message || 'Failed to delete');
        }
    }, [removeOwnedSession]);

    React.useEffect(() => {
        loadOwnedSessions();
    }, [loadOwnedSessions]);

    // Filter sessions to only show ones owned by this AD user
    const sessions = React.useMemo(() => {
        if (!ownershipLoaded) return [];
        return allSessions.filter(s => ownedSessionIds.has(s.id));
    }, [allSessions, ownedSessionIds, ownershipLoaded]);

    const handleLogout = React.useCallback(async () => {
        if (Platform.OS === 'web') {
            try { localStorage.removeItem('ad-username'); } catch {}
        }
        await auth.logout();
    }, [auth]);

    const handleCreateSession = React.useCallback(async () => {
        const onlineMachine = machines.find(m => isMachineOnline(m));
        if (!onlineMachine) {
            setError('No machine available');
            return;
        }

        setIsSpawning(true);
        setError(null);

        try {
            // Per-user directory isolation
            const baseDir = onlineMachine.metadata?.homeDir || '/home';
            const directory = `${baseDir}/nas-users/${username}`;
            const result = await machineSpawnNewSession({
                machineId: onlineMachine.id,
                directory,
                agent: 'claude',
                approvedNewDirectoryCreation: true,
            });

            if (result.type === 'success' && result.sessionId) {
                await sync.refreshSessions();
                storage.getState().updateSessionPermissionMode(result.sessionId, 'default');
                await addOwnedSession(result.sessionId);
                router.push(`/session/${result.sessionId}`);
            } else {
                const msg = result.type === 'error' ? result.errorMessage : 'Failed to create session';
                setError(msg);
            }
        } catch (e: any) {
            setError(e?.message || 'Failed to create session');
        } finally {
            setIsSpawning(false);
        }
    }, [machines, addOwnedSession, username, router]);

    // Show session list
    return (
        <View style={[styles.container, {
            backgroundColor: '#1a1a2e',
            paddingTop: insets.top,
        }]}>
            {/* Company brand header with user controls */}
            <CompanyHeader rightContent={
                <View style={{ flexDirection: 'row', alignItems: 'center', gap: 12 }}>
                    <Text style={{ color: '#ffffffcc', fontSize: 14 }}>{username}</Text>
                    <Pressable onPress={handleCreateSession} disabled={isSpawning}>
                        {isSpawning
                            ? <ActivityIndicator size="small" color="#ffffff" />
                            : <Ionicons name="add-circle-outline" size={24} color="#ffffff" />}
                    </Pressable>
                    <Pressable onPress={handleLogout}>
                        <Ionicons name="log-out-outline" size={22} color="#ffffffcc" />
                    </Pressable>
                </View>
            } />

            <View style={{ flex: 1, backgroundColor: theme.colors.groupped.background }}>

                {/* Error */}
                {error && (
                    <View style={styles.errorContainer}>
                        <Text style={styles.errorText}>{error}</Text>
                    </View>
                )}

                {/* Loading */}
                {(!isDataReady || !ownershipLoaded) && (
                    <View style={styles.centerContent}>
                        <ActivityIndicator size="large" color={theme.colors.textSecondary} />
                        <Text style={[styles.loadingText, { color: theme.colors.textSecondary }]}>
                            Connecting...
                        </Text>
                    </View>
                )}

                {/* Sessions list */}
                {isDataReady && ownershipLoaded && (
                    <FlatList
                        data={sessions}
                        keyExtractor={(item) => item.id}
                        style={styles.listOuter}
                        contentContainerStyle={[styles.listContent, { backgroundColor: theme.colors.surface }]}
                        renderItem={({ item, index }) => (
                            <SessionItem
                                session={item}
                                onPress={() => router.push(`/session/${item.id}`)}
                                onDelete={() => handleDeleteSession(item.id)}
                                isLast={index === sessions.length - 1}
                            />
                        )}
                        ListEmptyComponent={
                            <View style={styles.emptyContainer}>
                                <Text style={[styles.emptyText, { color: theme.colors.textSecondary }]}>
                                    No sessions yet
                                </Text>
                                <Text style={[styles.emptyHint, { color: theme.colors.textSecondary }]}>
                                    Tap + to start a new session
                                </Text>
                            </View>
                        }
                    />
                )}
            </View>
        </View>
    );
});

const SessionItem = React.memo(({ session, onPress, onDelete, isLast }: { session: Session; onPress: () => void; onDelete: () => void; isLast?: boolean }) => {
    const { theme } = useUnistyles();
    const status = useSessionStatus(session);
    const name = getSessionName(session);
    const subtitle = getSessionSubtitle(session);

    return (
        <Pressable
            onPress={onPress}
            style={({ pressed }) => [
                styles.sessionItem,
                {
                    backgroundColor: pressed ? theme.colors.groupped.pressed : theme.colors.surface,
                    borderBottomWidth: isLast ? 0 : 0.5,
                    borderBottomColor: isLast ? 'transparent' : theme.colors.border,
                },
            ]}
        >
            <StatusDot status={status} />
            <View style={styles.sessionInfo}>
                <Text style={[styles.sessionName, { color: theme.colors.text }]} numberOfLines={1}>
                    {name}
                </Text>
                <Text style={[styles.sessionSubtitle, { color: theme.colors.textSecondary }]} numberOfLines={1}>
                    {subtitle}
                </Text>
            </View>
            <Pressable
                onPress={(e) => { e.stopPropagation(); onDelete(); }}
                style={styles.deleteButton}
                hitSlop={8}
            >
                <Ionicons name="trash-outline" size={18} color="#e53935" />
            </Pressable>
            <Ionicons name="chevron-forward" size={18} color={theme.colors.textSecondary} />
        </Pressable>
    );
});

const styles = StyleSheet.create((theme) => ({
    container: {
        flex: 1,
    },
    header: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'space-between',
        paddingHorizontal: 16,
        paddingVertical: 12,
        borderBottomWidth: 0.5,
        borderBottomColor: theme.colors.border,
    },
    headerLeft: {
        flex: 1,
    },
    headerTitle: {
        fontSize: 20,
        ...Typography.default('bold'),
    },
    headerSubtitle: {
        fontSize: 13,
        ...Typography.default(),
        marginTop: 2,
    },
    headerRight: {
        flexDirection: 'row',
        alignItems: 'center',
        gap: 12,
    },
    headerButton: {
        padding: 4,
    },
    errorContainer: {
        paddingHorizontal: 16,
        paddingVertical: 8,
        backgroundColor: '#e5393520',
    },
    errorText: {
        color: '#e53935',
        fontSize: 14,
        ...Typography.default(),
    },
    centerContent: {
        flex: 1,
        alignItems: 'center',
        justifyContent: 'center',
    },
    loadingText: {
        fontSize: 16,
        marginTop: 12,
        ...Typography.default(),
    },
    listOuter: {
        maxWidth: 800,
        width: '100%' as any,
        alignSelf: 'center' as const,
        paddingHorizontal: 16,
        paddingTop: 16,
    },
    listContent: {
        borderRadius: 12,
        overflow: 'hidden' as const,
    },
    sessionItem: {
        flexDirection: 'row',
        alignItems: 'center',
        paddingHorizontal: 16,
        paddingVertical: 14,
        gap: 12,
    },
    sessionInfo: {
        flex: 1,
    },
    deleteButton: {
        padding: 6,
    },
    sessionName: {
        fontSize: 16,
        ...Typography.default('semiBold'),
    },
    sessionSubtitle: {
        fontSize: 13,
        marginTop: 2,
        ...Typography.default(),
    },
    emptyContainer: {
        alignItems: 'center',
        justifyContent: 'center',
        paddingTop: 80,
    },
    emptyText: {
        fontSize: 18,
        ...Typography.default('semiBold'),
    },
    emptyHint: {
        fontSize: 14,
        marginTop: 8,
        ...Typography.default(),
    },
}));
