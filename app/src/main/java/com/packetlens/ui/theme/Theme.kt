package com.packetlens.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext

private val DarkColorScheme = darkColorScheme(
    primary = Color(0xFF2196F3),
    secondary = Color(0xFF03DAC5),
    tertiary = Color(0xFFBB86FC),
    background = Color(0xFF0D1117),
    surface = Color(0xFF161B22),
    surfaceVariant = Color(0xFF21262D),
    onPrimary = Color.White,
    onSecondary = Color.Black,
    onBackground = Color(0xFFE6EDF3),
    onSurface = Color(0xFFE6EDF3),
    onSurfaceVariant = Color(0xFF8B949E),
    error = Color(0xFFFF6B6B)
)

private val LightColorScheme = lightColorScheme(
    primary = Color(0xFF1976D2),
    secondary = Color(0xFF00897B),
    tertiary = Color(0xFF7B1FA2),
    background = Color(0xFFF6F8FA),
    surface = Color.White,
    surfaceVariant = Color(0xFFE7E9EC),
    onPrimary = Color.White,
    onSecondary = Color.White,
    onBackground = Color(0xFF1F2328),
    onSurface = Color(0xFF1F2328),
    onSurfaceVariant = Color(0xFF656D76),
    error = Color(0xFFD32F2F)
)

@Composable
fun PacketLensTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    val colorScheme = when {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val context = LocalContext.current
            if (darkTheme) dynamicDarkColorScheme(context)
            else dynamicLightColorScheme(context)
        }
        darkTheme -> DarkColorScheme
        else -> LightColorScheme
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography = Typography(),
        content = content
    )
}
