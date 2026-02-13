import { RoundButton } from "@/components/RoundButton";
import { useAuth } from "@/auth/AuthContext";
import { Text, View, Image, Platform, TextInput } from "react-native";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import * as React from 'react';
import { encodeBase64 } from "@/encryption/base64";
import { authGetToken } from "@/auth/authGetToken";
import { router, useRouter } from "expo-router";
import { StyleSheet, useUnistyles } from "react-native-unistyles";
import { getRandomBytesAsync } from "expo-crypto";
import { useIsLandscape } from "@/utils/responsive";
import { Typography } from "@/constants/Typography";
import { trackAccountCreated, trackAccountRestored } from '@/track';
import { HomeHeaderNotAuth } from "@/components/HomeHeader";
import { MainView } from "@/components/MainView";
import { CompanyHeader } from "@/components/CompanyHeader";
import { t } from '@/text';
import { getServerUrl } from "@/sync/serverConfig";
import axios from 'axios';

// Module-level AD username, set during adLogin, read in Authenticated
let pendingAdUsername: string | null = null;

function getStoredAdUsername(): string | null {
    if (Platform.OS === 'web') {
        try { return localStorage.getItem('ad-username'); } catch {}
    }
    return null;
}

export default function Home() {
    const auth = useAuth();
    if (!auth.isAuthenticated) {
        return <NotAuthenticated />;
    }
    return (
        <Authenticated />
    )
}

function Authenticated() {
    const router = useRouter();

    React.useEffect(() => {
        const adUser = pendingAdUsername || getStoredAdUsername();
        if (adUser) {
            pendingAdUsername = null;
            router.replace(`/ad-user/${adUser}` as any);
        }
    }, []);

    // If AD user, show nothing while redirect fires
    if (pendingAdUsername || getStoredAdUsername()) {
        return null;
    }
    return <MainView variant="phone" />;
}

function NotAuthenticated() {
    const { theme } = useUnistyles();
    const auth = useAuth();
    const router = useRouter();
    const isLandscape = useIsLandscape();
    const insets = useSafeAreaInsets();

    const [username, setUsername] = React.useState('');
    const [password, setPassword] = React.useState('');
    const [error, setError] = React.useState('');

    const createAccount = async () => {
        try {
            const secret = await getRandomBytesAsync(32);
            const token = await authGetToken(secret);
            if (token && secret) {
                await auth.login(token, encodeBase64(secret, 'base64url'));
                trackAccountCreated();
            }
        } catch (error) {
            console.error('Error creating account', error);
        }
    }

    const adLogin = async () => {
        setError('');
        if (!username.trim() || !password.trim()) {
            setError('Please enter username and password');
            return;
        }
        try {
            const serverUrl = getServerUrl();
            const response = await axios.post(`${serverUrl}/v1/auth/ad`, {
                username: username.trim(),
                password: password.trim()
            });
            const { token, secret } = response.data;
            if (token && secret) {
                // Store AD username for redirect after auth
                const cleanName = username.trim().includes('\\')
                    ? username.trim().split('\\').pop()!
                    : username.trim();
                pendingAdUsername = cleanName;
                if (Platform.OS === 'web') {
                    try { localStorage.setItem('ad-username', cleanName); } catch {}
                }
                try {
                    await auth.login(token, secret);
                    trackAccountCreated();
                } catch (loginError: any) {
                    pendingAdUsername = null;
                    if (Platform.OS === 'web') {
                        try { localStorage.removeItem('ad-username'); } catch {}
                    }
                    console.error('Sync init error:', loginError);
                    setError('Sync init failed: ' + (loginError?.message || String(loginError)));
                }
            }
        } catch (e: any) {
            console.error('AD login error', e);
            setError(e?.response?.data?.error || e?.message || 'Login failed');
        }
    }

    const isWeb = Platform.OS !== 'android' && Platform.OS !== 'ios';

    const adLoginForm = (
        <View style={styles.adFormContainer}>
            <TextInput
                style={[styles.input, { color: theme.colors.text, borderColor: theme.colors.border }]}
                placeholder="Username"
                placeholderTextColor={theme.colors.textSecondary}
                value={username}
                onChangeText={setUsername}
                autoCapitalize="none"
                autoCorrect={false}
            />
            <TextInput
                style={[styles.input, { color: theme.colors.text, borderColor: theme.colors.border }]}
                placeholder="Password"
                placeholderTextColor={theme.colors.textSecondary}
                value={password}
                onChangeText={setPassword}
                secureTextEntry
                onSubmitEditing={adLogin}
            />
            {error ? <Text style={styles.errorText}>{error}</Text> : null}
            <View style={styles.buttonContainer}>
                <RoundButton
                    title="Login"
                    action={adLogin}
                />
            </View>
        </View>
    );

    const portraitLayout = (
        <View style={styles.portraitContainer}>
            <View style={styles.mascotWrapper}>
                <Image
                    source={require('@/assets/images/happy-nas.webp')}
                    resizeMode="contain"
                    style={styles.mascot}
                />
            </View>
            <Text style={styles.title}>
                {t('welcome.title')}
            </Text>
            <Text style={styles.subtitle}>
                {t('welcome.subtitle')}
            </Text>
            {isWeb ? (
                <>
                    {adLoginForm}
                </>
            ) : (
                <>
                    <View style={styles.buttonContainer}>
                        <RoundButton
                            title={t('welcome.createAccount')}
                            action={createAccount}
                        />
                    </View>
                    <View style={styles.buttonContainerSecondary}>
                        <RoundButton
                            size="normal"
                            title={t('welcome.linkOrRestoreAccount')}
                            onPress={() => {
                                trackAccountRestored();
                                router.push('/restore');
                            }}
                            display="inverted"
                        />
                    </View>
                </>
            )}
        </View>
    );

    const landscapeLayout = (
        <View style={[styles.landscapeContainer, { paddingBottom: insets.bottom + 24 }]}>
            <View style={styles.landscapeInner}>
                <View style={styles.landscapeLogoSection}>
                    <View style={styles.mascotWrapper}>
                        <Image
                            source={require('@/assets/images/happy-nas.webp')}
                            resizeMode="contain"
                            style={{ width: 200, height: 200 }}
                        />
                    </View>
                </View>
                <View style={styles.landscapeContentSection}>
                    <Text style={styles.landscapeTitle}>
                        {t('welcome.title')}
                    </Text>
                    <Text style={styles.landscapeSubtitle}>
                        {t('welcome.subtitle')}
                    </Text>
                    {isWeb
                        ? adLoginForm
                        : (<>
                            <View style={styles.landscapeButtonContainer}>
                                <RoundButton
                                    title={t('welcome.createAccount')}
                                    action={createAccount}
                                />
                            </View>
                            <View style={styles.landscapeButtonContainerSecondary}>
                                <RoundButton
                                    size="normal"
                                    title={t('welcome.linkOrRestoreAccount')}
                                    onPress={() => {
                                        trackAccountRestored();
                                        router.push('/restore');
                                    }}
                                    display="inverted"
                                />
                            </View>
                        </>)
                    }
                </View>
            </View>
        </View>
    );

    return (
        <View style={{ flex: 1, backgroundColor: '#1a1a2e' }}>
            <View style={{ paddingTop: insets.top }}>
                <CompanyHeader />
            </View>
            <View style={{ flex: 1, backgroundColor: theme.colors.groupped.background }}>
                {isLandscape ? landscapeLayout : portraitLayout}
            </View>
        </View>
    )
}

const styles = StyleSheet.create((theme) => ({
    // NotAuthenticated styles
    portraitContainer: {
        flex: 1,
        alignItems: 'center',
        justifyContent: 'center',
    },
    mascotWrapper: {
        marginBottom: 8,
        borderRadius: 25,
        overflow: 'hidden' as const,
        // @ts-ignore - Web CSS mask for feathered edges
        maskImage: 'radial-gradient(ellipse 80% 80% at center, black 50%, transparent 100%)',
        WebkitMaskImage: 'radial-gradient(ellipse 80% 80% at center, black 50%, transparent 100%)',
    } as any,
    mascot: {
        width: 220,
        height: 220,
        borderRadius: 25,
    },
    title: {
        marginTop: 8,
        textAlign: 'center',
        fontSize: 24,
        ...Typography.default('semiBold'),
        color: theme.colors.text,
    },
    subtitle: {
        ...Typography.default(),
        fontSize: 18,
        color: theme.colors.textSecondary,
        marginTop: 16,
        textAlign: 'center',
        marginHorizontal: 24,
        marginBottom: 64,
    },
    buttonContainer: {
        maxWidth: 280,
        width: '100%',
        marginBottom: 16,
    },
    buttonContainerSecondary: {
    },
    // Landscape styles
    landscapeContainer: {
        flexBasis: 0,
        flexGrow: 1,
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'center',
        paddingHorizontal: 48,
    },
    landscapeInner: {
        flexGrow: 1,
        flexBasis: 0,
        maxWidth: 800,
        flexDirection: 'row',
    },
    landscapeLogoSection: {
        flexBasis: 0,
        flexGrow: 1,
        alignItems: 'center',
        justifyContent: 'center',
        paddingRight: 24,
    },
    landscapeContentSection: {
        flexBasis: 0,
        flexGrow: 1,
        alignItems: 'center',
        justifyContent: 'center',
        paddingLeft: 24,
    },
    landscapeTitle: {
        textAlign: 'center',
        fontSize: 24,
        ...Typography.default('semiBold'),
        color: theme.colors.text,
    },
    landscapeSubtitle: {
        ...Typography.default(),
        fontSize: 18,
        color: theme.colors.textSecondary,
        marginTop: 16,
        textAlign: 'center',
        marginBottom: 32,
        paddingHorizontal: 16,
    },
    landscapeButtonContainer: {
        width: 280,
        marginBottom: 16,
    },
    landscapeButtonContainerSecondary: {
        width: 280,
    },
    // AD Login form styles
    adFormContainer: {
        width: '100%',
        maxWidth: 320,
        alignItems: 'center',
    },
    input: {
        width: '100%',
        height: 44,
        borderWidth: 1,
        borderRadius: 8,
        paddingHorizontal: 12,
        marginBottom: 12,
        fontSize: 16,
        ...Typography.default(),
    },
    errorText: {
        color: '#e53935',
        fontSize: 14,
        marginBottom: 8,
        textAlign: 'center',
        ...Typography.default(),
    },
}));