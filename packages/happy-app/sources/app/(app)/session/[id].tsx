import * as React from 'react';
import { View } from 'react-native';
import { useRoute } from "@react-navigation/native";
import { useRouter } from 'expo-router';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { SessionView } from '@/-session/SessionView';
import { CompanyHeader, COMPANY_HEADER_HEIGHT } from '@/components/CompanyHeader';


export default React.memo(() => {
    const route = useRoute();
    const router = useRouter();
    const sessionId = (route.params! as any).id as string;
    const insets = useSafeAreaInsets();

    return (
        <View style={{ flex: 1 }}>
            <SessionView id={sessionId} extraTopPadding={0} />
            {/* Company brand header overlays the safe area zone */}
            <View style={{
                position: 'absolute',
                top: 0,
                left: 0,
                right: 0,
                paddingTop: insets.top,
                backgroundColor: '#1a1a2e',
                zIndex: 1001,
            }}>
                <CompanyHeader onLogoPress={() => router.replace('/')} />
            </View>
        </View>
    );
});
