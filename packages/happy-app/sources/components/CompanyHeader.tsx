import * as React from 'react';
import { View, Text, Image, Pressable } from 'react-native';
import { Typography } from '@/constants/Typography';

export const COMPANY_HEADER_HEIGHT = 54;
const BG_COLOR = '#1a1a2e';

interface CompanyHeaderProps {
    onLogoPress?: () => void;
    rightContent?: React.ReactNode;
}

export const CompanyHeader = React.memo((props: CompanyHeaderProps) => {
    const [time, setTime] = React.useState(new Date());

    React.useEffect(() => {
        const timer = setInterval(() => setTime(new Date()), 1000);
        return () => clearInterval(timer);
    }, []);

    const formattedTime = React.useMemo(() => {
        const y = time.getFullYear();
        const m = String(time.getMonth() + 1).padStart(2, '0');
        const d = String(time.getDate()).padStart(2, '0');
        const h = time.getHours();
        const min = String(time.getMinutes()).padStart(2, '0');
        const period = h < 12 ? '上午' : '下午';
        const h12 = h % 12 || 12;
        return `${y}/${m}/${d} ${period} ${h12}:${min}`;
    }, [time]);

    const logo = (
        <Image
            source={require('@/assets/images/indi-logo.svg')}
            style={{ width: 130, height: 37 }}
            resizeMode="contain"
        />
    );

    return (
        <View style={{
            height: COMPANY_HEADER_HEIGHT,
            backgroundColor: BG_COLOR,
            flexDirection: 'row',
            alignItems: 'center',
            justifyContent: 'space-between',
            paddingHorizontal: 16,
        }}>
            {props.onLogoPress ? (
                <Pressable onPress={props.onLogoPress} hitSlop={8}>
                    {logo}
                </Pressable>
            ) : logo}

            {props.rightContent ?? (
                <Text style={{ color: '#ffffffcc', fontSize: 14, ...Typography.default() }}>
                    {formattedTime}
                </Text>
            )}
        </View>
    );
});
